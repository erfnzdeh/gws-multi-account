// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::json;

use crate::credential_store;
use crate::error::GwsError;

/// Response from Google's token endpoint
#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    #[allow(dead_code)]
    expires_in: u64,
    #[allow(dead_code)]
    token_type: String,
}

/// Exchange authorization code for tokens using reqwest (supports HTTP proxy)
async fn exchange_code_with_reqwest(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuthTokenResponse, GwsError> {
    let client = crate::client::shared_client()?;
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("grant_type", "authorization_code"),
    ];

    let response = client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .map_err(|e| GwsError::Auth(format!("Failed to send token request: {e}")))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = crate::auth::response_text_or_placeholder(response.text().await);
        return Err(GwsError::Auth(format!(
            "Token exchange failed with status {}: {}",
            status, body
        )));
    }

    response
        .json()
        .await
        .map_err(|e| GwsError::Auth(format!("Failed to parse token response: {e}")))
}

/// Extra query parameters added to the OAuth consent URL.
#[derive(Debug, Default, Clone)]
struct AuthUrlExtras {
    /// Pre-selects this Google account in the consent screen.
    login_hint: Option<String>,
    /// Incremental auth: the new grant also covers previously granted scopes.
    include_granted_scopes: bool,
}

impl AuthUrlExtras {
    fn apply(&self, url: &str) -> String {
        let mut params = Vec::new();
        if let Some(hint) = &self.login_hint {
            params.push(format!("login_hint={}", urlencoding(hint)));
        }
        if self.include_granted_scopes {
            params.push("include_granted_scopes=true".to_string());
        }
        if params.is_empty() {
            return url.to_string();
        }
        let sep = if url.contains('?') { '&' } else { '?' };
        format!("{url}{sep}{}", params.join("&"))
    }
}

fn build_proxy_auth_url(
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
    extras: &AuthUrlExtras,
) -> String {
    let scopes_str = scopes.join(" ");
    let url = format!(
        "https://accounts.google.com/o/oauth2/auth?\
         scope={}&\
         access_type=offline&\
         redirect_uri={}&\
         response_type=code&\
         client_id={}&\
         prompt=select_account+consent",
        urlencoding(&scopes_str),
        urlencoding(redirect_uri),
        urlencoding(client_id)
    );
    extras.apply(&url)
}

fn extract_authorization_code(request_line: &str) -> Result<String, GwsError> {
    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| GwsError::Auth("Invalid HTTP request".to_string()))?;

    path.split('?')
        .nth(1)
        .and_then(|query| {
            query.split('&').find_map(|pair| {
                let mut parts = pair.split('=');
                if parts.next() == Some("code") {
                    parts.next().map(|value| value.to_string())
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| GwsError::Auth("No authorization code in callback".to_string()))
}

/// Perform OAuth login flow with proxy support using reqwest for token exchange
async fn login_with_proxy_support(
    client_id: &str,
    client_secret: &str,
    scopes: &[String],
    extras: &AuthUrlExtras,
) -> Result<(String, String), GwsError> {
    // Start local server to receive OAuth callback
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| GwsError::Auth(format!("Failed to start local server: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| GwsError::Auth(format!("Failed to inspect local server: {e}")))?
        .port();
    let redirect_uri = format!("http://localhost:{}", port);

    let auth_url = build_proxy_auth_url(client_id, &redirect_uri, scopes, extras);

    println!("Open this URL in your browser to authenticate:\n");
    println!("  {}\n", auth_url);

    // Wait for OAuth callback
    let (mut stream, _) = listener
        .accept()
        .map_err(|e| GwsError::Auth(format!("Failed to accept connection: {e}")))?;

    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| GwsError::Auth(format!("Failed to read request: {e}")))?;

    let code = extract_authorization_code(&request_line)?;

    // Send success response to browser
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
        <html><body><h1>Success!</h1><p>You may now close this window.</p></body></html>";
    let _ = stream.write_all(response.as_bytes());

    // Exchange code for tokens using reqwest (proxy-aware)
    let token_response =
        exchange_code_with_reqwest(client_id, client_secret, &code, &redirect_uri).await?;

    let refresh_token = token_response.refresh_token.ok_or_else(|| {
        GwsError::Auth(
            "OAuth flow completed but no refresh token was returned. \
                 Ensure the OAuth consent screen includes 'offline' access."
                .to_string(),
        )
    })?;

    Ok((token_response.access_token, refresh_token))
}

fn read_refresh_token_from_cache(temp_path: &Path) -> Result<String, GwsError> {
    let token_data = std::fs::read(temp_path)
        .ok()
        .and_then(|bytes| crate::credential_store::decrypt(&bytes).ok())
        .and_then(|decrypted| String::from_utf8(decrypted).ok())
        .unwrap_or_default();

    extract_refresh_token(&token_data).ok_or_else(|| {
        GwsError::Auth(
            "OAuth flow completed but no refresh token was returned. \
             Ensure the OAuth consent screen includes 'offline' access."
                .to_string(),
        )
    })
}

async fn login_with_yup_oauth(
    config_dir: &Path,
    client_id: &str,
    client_secret: &str,
    scopes: &[String],
    extras: &AuthUrlExtras,
) -> Result<(String, String), GwsError> {
    let secret = yup_oauth2::ApplicationSecret {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        auth_uri: "https://accounts.google.com/o/oauth2/auth".to_string(),
        token_uri: "https://oauth2.googleapis.com/token".to_string(),
        redirect_uris: vec!["http://localhost".to_string()],
        ..Default::default()
    };

    let temp_path = config_dir.join("credentials.tmp");
    let _ = std::fs::remove_file(&temp_path);

    let result = async {
        let auth = yup_oauth2::InstalledFlowAuthenticator::builder(
            secret,
            yup_oauth2::InstalledFlowReturnMethod::HTTPRedirect,
        )
        .with_storage(Box::new(crate::token_storage::EncryptedTokenStorage::new(
            temp_path.clone(),
        )))
        .force_account_selection(true)
        .flow_delegate(Box::new(CliFlowDelegate {
            extras: extras.clone(),
        }))
        .build()
        .await
        .map_err(|e| GwsError::Auth(format!("Failed to build authenticator: {e}")))?;

        let scope_refs: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
        let token = auth
            .token(&scope_refs)
            .await
            .map_err(|e| GwsError::Auth(format!("OAuth flow failed: {e}")))?;

        let access_token = token
            .token()
            .ok_or_else(|| GwsError::Auth("No access token returned".to_string()))?
            .to_string();
        let refresh_token = read_refresh_token_from_cache(&temp_path)?;

        Ok((access_token, refresh_token))
    }
    .await;

    let _ = std::fs::remove_file(&temp_path);
    result
}

/// Simple URL encoding
fn urlencoding(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Mask a secret string by showing only the first 4 and last 4 characters.
/// Strings with 8 or fewer characters are fully replaced with "***".
///
/// Uses char-based indexing (not byte offsets) so multi-byte UTF-8 secrets
/// never cause a panic.
fn mask_secret(s: &str) -> String {
    const MASK_PREFIX_LEN: usize = 4;
    const MASK_SUFFIX_LEN: usize = 4;
    const MIN_LEN_FOR_PARTIAL_MASK: usize = MASK_PREFIX_LEN + MASK_SUFFIX_LEN;

    let char_count = s.chars().count();
    if char_count > MIN_LEN_FOR_PARTIAL_MASK {
        let prefix: String = s.chars().take(MASK_PREFIX_LEN).collect();
        let suffix: String = s.chars().skip(char_count - MASK_SUFFIX_LEN).collect();
        format!("{prefix}...{suffix}")
    } else {
        "***".to_string()
    }
}

/// Minimal scopes for first-run login — only core Workspace APIs that never
/// trigger Google's `restricted_client` / unverified-app block.
///
/// These are the safest scopes for unverified OAuth apps and personal Cloud
/// projects.  Users can request broader access with `--scopes` or `--full`.
pub const MINIMAL_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/presentations",
    "https://www.googleapis.com/auth/tasks",
];

/// Default scopes for login.  Alias for [`MINIMAL_SCOPES`] — deliberately kept
/// narrow so first-run logins succeed even with an unverified OAuth app.
///
/// Previously this included `pubsub` and `cloud-platform`, which Google marks
/// as *restricted* and blocks for unverified apps, causing `Error 403:
/// restricted_client`.  Use `--scopes` to add those scopes explicitly when you
/// have a verified app or a GCP project with the APIs enabled and approved.
pub const DEFAULT_SCOPES: &[&str] = MINIMAL_SCOPES;

/// Full scopes — all common Workspace APIs plus GCP platform access.
///
/// Use `gws auth login --full` to request these.  Unverified OAuth apps will
/// receive a Google consent-screen warning, and some scopes (e.g. `pubsub`,
/// `cloud-platform`) require app verification or a Workspace domain admin to
/// grant access.
pub const FULL_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/presentations",
    "https://www.googleapis.com/auth/tasks",
    "https://www.googleapis.com/auth/pubsub",
    "https://www.googleapis.com/auth/cloud-platform",
];

/// Readonly scopes — read-only Workspace access.
const READONLY_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/spreadsheets.readonly",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/documents.readonly",
    "https://www.googleapis.com/auth/presentations.readonly",
    "https://www.googleapis.com/auth/tasks.readonly",
];

pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("GOOGLE_WORKSPACE_CLI_CONFIG_DIR") {
        return PathBuf::from(dir);
    }

    // Use ~/.config/gws on all platforms for a consistent, user-friendly path.
    let primary = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("gws");
    if primary.exists() {
        return primary;
    }

    // Backward compat: fall back to OS-specific config dir for existing installs
    // (e.g. ~/Library/Application Support/gws on macOS, %APPDATA%\gws on Windows).
    let legacy = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("gws");
    if legacy.exists() {
        return legacy;
    }

    primary
}

fn plain_credentials_path() -> PathBuf {
    if let Ok(path) = std::env::var("GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE") {
        return PathBuf::from(path);
    }
    crate::accounts::credential_dir().join("credentials.json")
}

fn token_cache_path() -> PathBuf {
    crate::accounts::credential_dir().join("token_cache.json")
}

/// Which scope set to use for login.
enum ScopeMode {
    /// Use the default scopes (MINIMAL_SCOPES).
    Default,
    /// Use readonly scopes.
    Readonly,
    /// Use full scopes (incl. pubsub + cloud-platform).
    Full,
    /// Use explicitly provided custom scopes.
    Custom(Vec<String>),
}

/// Build the clap Command for the `login` subcommand.
/// Used by both `auth_command()` and `login_command()` as single source of truth.
fn build_login_subcommand() -> clap::Command {
    clap::Command::new("login")
        .about("Authenticate via OAuth2 (opens browser)")
        .arg(
            clap::Arg::new("readonly")
                .long("readonly")
                .help("Request read-only scopes")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(["full", "scopes"]),
        )
        .arg(
            clap::Arg::new("full")
                .long("full")
                .help("Request all scopes incl. pubsub + cloud-platform")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with_all(["readonly", "scopes"]),
        )
        .arg(
            clap::Arg::new("scopes")
                .long("scopes")
                .help("Comma-separated custom scopes")
                .value_name("scopes")
                .conflicts_with_all(["readonly", "full"]),
        )
        .arg(
            clap::Arg::new("services")
                .short('s')
                .long("services")
                .help(
                    "Comma-separated service names to limit scope picker (e.g. drive,gmail,sheets)",
                )
                .value_name("services"),
        )
        .arg(account_arg(
            "Account to log in to. Pre-selects it in the browser and rejects a different one",
        ))
        .arg(
            clap::Arg::new("client-secret")
                .long("client-secret")
                .help("OAuth client file to use for this account only (e.g. one created inside a Workspace org)")
                .value_name("PATH"),
        )
}

/// `--account` as documented on auth subcommands. The value itself is taken
/// out of argv in `main` (see `accounts::take_account_flag`), so clap only
/// uses this for help output.
fn account_arg(help: &'static str) -> clap::Arg {
    clap::Arg::new("account")
        .long("account")
        .help(help)
        .value_name("EMAIL")
}

/// Build the clap Command for `gws auth`.
fn auth_command() -> clap::Command {
    clap::Command::new("auth")
        .about("Manage authentication for Google Workspace APIs")
        .subcommand_required(false)
        .subcommand(build_login_subcommand())
        .subcommand(
            clap::Command::new("setup")
                .about("Configure GCP project + OAuth client (requires gcloud)")
                .disable_help_flag(true)
                // setup has its own clap-based arg parsing in setup.rs,
                // so we pass remaining args through.
                .arg(
                    clap::Arg::new("args")
                        .trailing_var_arg(true)
                        .allow_hyphen_values(true)
                        .num_args(0..)
                        .value_name("ARGS"),
                ),
        )
        .subcommand(
            clap::Command::new("status")
                .about("Show current authentication state")
                .arg(account_arg("Account to inspect (default: the default account)")),
        )
        .subcommand(
            clap::Command::new("export")
                .about("Print decrypted credentials to stdout")
                .arg(
                    clap::Arg::new("unmasked")
                        .long("unmasked")
                        .help("Show secrets without masking")
                        .action(clap::ArgAction::SetTrue),
                )
                .arg(account_arg("Account to export (default: the default account)")),
        )
        .subcommand(
            clap::Command::new("logout")
                .about("Clear saved credentials and token cache")
                .arg(account_arg(
                    "Account to log out (required when several accounts are configured)",
                ))
                .arg(
                    clap::Arg::new("revoke")
                        .long("revoke")
                        .help("Also revoke the refresh token at Google")
                        .action(clap::ArgAction::SetTrue),
                ),
        )
        .subcommand(clap::Command::new("list").about("List configured accounts and the default"))
        .subcommand(
            clap::Command::new("default")
                .about("Set the default account (used for reads when --account is omitted)")
                .arg(
                    clap::Arg::new("email")
                        .required(true)
                        .value_name("EMAIL"),
                ),
        )
        .subcommand(
            clap::Command::new("import")
                .about("Import the account from another (single-account) gws config directory")
                .arg(
                    clap::Arg::new("from")
                        .long("from")
                        .required(true)
                        .value_name("DIR")
                        .help("Config directory to import from, e.g. ~/.config/gws-work"),
                )
                .arg(
                    clap::Arg::new("keyring-backend")
                        .long("keyring-backend")
                        .value_parser(["keyring", "file"])
                        .default_value("keyring")
                        .help("Where that directory's encryption key lives: keyring, or its .encryption_key file"),
                ),
        )
}

/// Handle `gws auth <subcommand>`.
pub async fn handle_auth_command(args: &[String]) -> Result<(), GwsError> {
    let matches = match auth_command()
        .try_get_matches_from(std::iter::once("auth".to_string()).chain(args.iter().cloned()))
    {
        Ok(m) => m,
        Err(e)
            if e.kind() == clap::error::ErrorKind::DisplayHelp
                || e.kind() == clap::error::ErrorKind::DisplayVersion =>
        {
            e.print().map_err(|io_err| {
                GwsError::Validation(format!("Failed to print help: {io_err}"))
            })?;
            return Ok(());
        }
        Err(e) => return Err(GwsError::Validation(e.to_string())),
    };

    match matches.subcommand() {
        Some(("login", sub_m)) => {
            let (scope_mode, services_filter, client_secret) = parse_login_args(sub_m)?;

            handle_login_inner(scope_mode, services_filter, client_secret).await
        }
        Some(("setup", sub_m)) => {
            // Collect remaining args and delegate to setup's own clap parser.
            let setup_args: Vec<String> = sub_m
                .get_many::<String>("args")
                .map(|vals| vals.cloned().collect())
                .unwrap_or_default();
            crate::setup::run_setup(&setup_args).await
        }
        Some(("status", _)) => {
            select_account_for_auth(crate::accounts::Access::Read)?;
            handle_status().await
        }
        Some(("export", sub_m)) => {
            let unmasked = sub_m.get_flag("unmasked");
            select_account_for_auth(crate::accounts::Access::Read)?;
            handle_export(unmasked).await
        }
        Some(("logout", sub_m)) => {
            // Logging out destroys credentials, so it follows the write rule.
            select_account_for_auth(crate::accounts::Access::Write)?;
            handle_logout(sub_m.get_flag("revoke")).await
        }
        Some(("list", _)) => handle_list(),
        Some(("default", sub_m)) => {
            let email = sub_m
                .get_one::<String>("email")
                .map(String::as_str)
                .unwrap_or_default();
            handle_default(email)
        }
        Some(("import", sub_m)) => {
            let from = sub_m
                .get_one::<String>("from")
                .map(String::as_str)
                .unwrap_or_default();
            let file_backend = sub_m
                .get_one::<String>("keyring-backend")
                .map(String::as_str)
                == Some("file");
            handle_import(from, file_backend).await
        }
        _ => {
            // No subcommand → print help
            auth_command()
                .print_help()
                .map_err(|e| GwsError::Validation(format!("Failed to print help: {e}")))?;
            Ok(())
        }
    }
}

/// Build the clap Command for `gws auth login` (used by `run_login` for
/// standalone parsing when called from setup.rs).
fn login_command() -> clap::Command {
    build_login_subcommand()
}

/// Extract `ScopeMode` and optional services filter from parsed login args.
type LoginArgs = (ScopeMode, Option<HashSet<String>>, Option<PathBuf>);

fn parse_login_args(matches: &clap::ArgMatches) -> Result<LoginArgs, GwsError> {
    let scope_mode = if let Some(scopes_str) = matches.get_one::<String>("scopes") {
        ScopeMode::Custom(
            scopes_str
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
        )
    } else if matches.get_flag("readonly") {
        ScopeMode::Readonly
    } else if matches.get_flag("full") {
        ScopeMode::Full
    } else {
        ScopeMode::Default
    };

    let services_filter: Option<HashSet<String>> = matches.get_one::<String>("services").map(|v| {
        v.split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    });

    let client_secret = matches
        .get_one::<String>("client-secret")
        .map(|p| crate::validate::validate_safe_file_path(p, "--client-secret"))
        .transpose()?;

    Ok((scope_mode, services_filter, client_secret))
}

/// Run the `auth login` flow.
///
/// Exposed for internal orchestration (e.g. `auth setup --login`).
/// Accepts raw args for backward compat with setup.rs calling `run_login(&[])`.
pub async fn run_login(args: &[String]) -> Result<(), GwsError> {
    let matches = match login_command()
        .try_get_matches_from(std::iter::once("login".to_string()).chain(args.iter().cloned()))
    {
        Ok(m) => m,
        Err(e)
            if e.kind() == clap::error::ErrorKind::DisplayHelp
                || e.kind() == clap::error::ErrorKind::DisplayVersion =>
        {
            e.print().map_err(|io_err| {
                GwsError::Validation(format!("Failed to print help: {io_err}"))
            })?;
            return Ok(());
        }
        Err(e) => return Err(GwsError::Validation(e.to_string())),
    };

    let (scope_mode, services_filter, client_secret) = parse_login_args(&matches)?;

    handle_login_inner(scope_mode, services_filter, client_secret).await
}
/// Custom delegate that prints the OAuth URL on its own line for easy copying.
/// Adds `login_hint` / `include_granted_scopes` to the URL when requested.
struct CliFlowDelegate {
    extras: AuthUrlExtras,
}

impl yup_oauth2::authenticator_delegate::InstalledFlowDelegate for CliFlowDelegate {
    fn present_user_url<'a>(
        &'a self,
        url: &'a str,
        _need_code: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send + 'a>>
    {
        Box::pin(async move {
            let display_url = self.extras.apply(url);
            eprintln!("Open this URL in your browser to authenticate:\n");
            eprintln!("  {display_url}\n");
            Ok(String::new())
        })
    }
}

/// Where a login stores its credentials.
#[derive(Debug, Clone, PartialEq)]
enum LoginTarget {
    /// A config directory with single-account credentials and no registry:
    /// overwrite them, as before multi-account support.
    Legacy,
    /// Add or update an account in the registry. `requested` is the account
    /// named by `--account` / `GOOGLE_WORKSPACE_CLI_ACCOUNT`, if any.
    Account {
        requested: Option<String>,
        registry: crate::accounts::Registry,
    },
}

impl LoginTarget {
    /// A fresh config directory starts a registry; one that already holds
    /// single-account credentials keeps working the old way until imported.
    fn decide(config: &Path, requested: Option<&str>) -> Result<Self, GwsError> {
        let registry = crate::accounts::Registry::load(config)?;
        let requested = requested
            .map(crate::accounts::normalize_email)
            .transpose()?;
        let has_legacy_credentials =
            config.join("credentials.enc").exists() || config.join("credentials.json").exists();
        match registry {
            Some(registry) => Ok(Self::Account {
                requested,
                registry,
            }),
            None if !has_legacy_credentials => Ok(Self::Account {
                requested,
                registry: crate::accounts::Registry::default(),
            }),
            None => match requested {
                None => Ok(Self::Legacy),
                Some(email) => Err(GwsError::Account {
                    reason: "noAccountRegistry".to_string(),
                    message: format!(
                        "{} holds single-account credentials and no account registry. \
                         Run `gws auth import --from {}` first, then log in to {email}.",
                        config.display(),
                        config.display()
                    ),
                    accounts: Vec::new(),
                    default: None,
                }),
            },
        }
    }
}

/// Reads an OAuth client file (Google Cloud Console "installed" format).
fn load_client_secret_file(path: &Path) -> Result<crate::oauth_config::ClientSecretFile, GwsError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| GwsError::Validation(format!("Cannot read {}: {e}", path.display())))?;
    serde_json::from_str(&text).map_err(|_| {
        GwsError::Validation(format!(
            "{} is not an OAuth client file (expected the \"installed\" JSON downloaded from Google Cloud Console)",
            path.display()
        ))
    })
}

/// Google caps unverified (testing-mode) OAuth apps at this many scopes.
const UNVERIFIED_APP_SCOPE_LIMIT: usize = 25;

/// Inner login implementation that takes already-parsed options.
async fn handle_login_inner(
    scope_mode: ScopeMode,
    services_filter: Option<HashSet<String>>,
    client_secret_path: Option<PathBuf>,
) -> Result<(), GwsError> {
    let config = config_dir();
    let requested = crate::accounts::requested_account();
    let target = LoginTarget::decide(&config, requested.as_deref())?;

    if client_secret_path.is_some() && target == LoginTarget::Legacy {
        return Err(GwsError::Validation(
            "--client-secret needs an account registry. Run `gws auth import --from <dir>` first."
                .to_string(),
        ));
    }

    // When the account is known up front, select it now so its own OAuth
    // client (if any) is used and its stored scopes can be merged.
    let mut previous_scopes = Vec::new();
    if let LoginTarget::Account {
        requested: Some(email),
        registry,
    } = &target
    {
        if let Some(meta) = registry.accounts.get(email) {
            previous_scopes = meta.scopes.clone();
        }
        crate::accounts::set_active(crate::accounts::Active::Account(
            crate::accounts::Selection {
                email: email.clone(),
                dir: crate::accounts::account_dir(&config, email),
                source: crate::accounts::Source::Flag,
            },
        ));
    }

    // Resolve client_id and client_secret:
    // 0. --client-secret (pinned to this account only)
    // 1. Env vars
    // 2. The account's own client_secret.json, then the shared one
    let own_client = client_secret_path
        .as_deref()
        .map(load_client_secret_file)
        .transpose()?;
    let (client_id, client_secret, project_id) = match &own_client {
        Some(file) => (
            file.installed.client_id.clone(),
            file.installed.client_secret.clone(),
            Some(file.installed.project_id.clone()).filter(|p| !p.is_empty()),
        ),
        None => resolve_client_credentials()?,
    };

    // Persist credentials to client_secret.json if not already saved,
    // so they survive env var removal or shell session changes.
    if own_client.is_none() && !crate::oauth_config::client_config_path().exists() {
        let _ = crate::oauth_config::save_client_config(
            &client_id,
            &client_secret,
            project_id.as_deref().unwrap_or(""),
        );
    }

    // Determine scopes: explicit flags > interactive TUI > defaults
    let scopes = resolve_scopes(scope_mode, project_id.as_deref(), services_filter.as_ref()).await;

    // Remove restrictive scopes when broader alternatives are present.
    let mut scopes = filter_redundant_restrictive_scopes(scopes);

    // Ensure openid + email + profile scopes are always present so we can
    // identify the user via the userinfo endpoint after login, and so the
    // Gmail helpers can fall back to the People API to populate the From
    // display name when the send-as identity lacks one (Workspace accounts).
    let identity_scopes = [
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ];
    for s in &identity_scopes {
        if !scopes.iter().any(|existing| existing == s) {
            scopes.push(s.to_string());
        }
    }

    // Re-logging into an account adds scopes instead of replacing them.
    let is_account = matches!(target, LoginTarget::Account { .. });
    if is_account {
        scopes = crate::accounts::merge_scopes(&previous_scopes, &scopes);
        if scopes.len() > UNVERIFIED_APP_SCOPE_LIMIT {
            eprintln!(
                "Warning: requesting {} scopes. Unverified (testing-mode) OAuth apps are limited to {UNVERIFIED_APP_SCOPE_LIMIT}.",
                scopes.len()
            );
        }
    }

    // Ensure config directory exists
    std::fs::create_dir_all(&config)
        .map_err(|e| GwsError::Validation(format!("Failed to create config directory: {e}")))?;

    let extras = AuthUrlExtras {
        login_hint: match &target {
            LoginTarget::Account { requested, .. } => requested.clone(),
            LoginTarget::Legacy => None,
        },
        include_granted_scopes: is_account,
    };

    // If proxy env vars are set, use proxy-aware OAuth flow (reqwest)
    // Otherwise use yup-oauth2 (faster, but doesn't support proxy)
    let (access_token, refresh_token) = if crate::auth::has_proxy_env() {
        login_with_proxy_support(&client_id, &client_secret, &scopes, &extras).await?
    } else {
        login_with_yup_oauth(&config, &client_id, &client_secret, &scopes, &extras).await?
    };

    // Build credentials in the standard authorized_user format
    let creds_json = json!({
        "type": "authorized_user",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    });

    let creds_str = serde_json::to_string_pretty(&creds_json)
        .map_err(|e| GwsError::Validation(format!("Failed to serialize credentials: {e}")))?;

    // Fetch the user's email from Google userinfo
    let actual_email = fetch_userinfo_email(&access_token).await;

    let mut output = match target {
        LoginTarget::Legacy => {
            let enc_path = credential_store::save_encrypted(&creds_str)
                .map_err(|e| GwsError::Auth(format!("Failed to encrypt credentials: {e}")))?;
            // Tokens cached for the previous login may belong to another
            // account (#780); drop them.
            clear_account_caches(&config);
            json!({
                "status": "success",
                "message": "Authentication successful. Encrypted credentials saved.",
                "account": actual_email.as_deref().unwrap_or("(unknown)"),
                "credentials_file": enc_path.display().to_string(),
            })
        }
        LoginTarget::Account {
            requested,
            mut registry,
        } => {
            let email = actual_email
                .as_deref()
                .ok_or_else(|| {
                    GwsError::Auth(
                        "Signed in, but could not determine the account's email. Nothing was saved."
                            .to_string(),
                    )
                })
                .and_then(crate::accounts::normalize_email)?;
            check_login_email(requested.as_deref(), &email, &registry)?;

            let dir = crate::accounts::account_dir(&config, &email);
            crate::accounts::create_private_dir(&dir)?;
            if requested.is_none() {
                crate::accounts::set_active(crate::accounts::Active::Account(
                    crate::accounts::Selection {
                        email: email.clone(),
                        dir: dir.clone(),
                        source: crate::accounts::Source::Flag,
                    },
                ));
            }
            let enc_path = crate::credential_store::save_encrypted_to(
                &dir.join("credentials.enc"),
                &creds_str,
            )
            .map_err(|e| GwsError::Auth(format!("Failed to encrypt credentials: {e}")))?;
            clear_account_caches(&dir);
            if let Some(file) = &own_client {
                let json = serde_json::to_string_pretty(file)
                    .map_err(|e| GwsError::Other(anyhow::anyhow!(e)))?;
                let path = dir.join(crate::oauth_config::CLIENT_SECRET_FILE);
                crate::fs_util::atomic_write(&path, json.as_bytes()).map_err(|e| {
                    GwsError::Validation(format!("Failed to write {}: {e}", path.display()))
                })?;
            }

            registry.upsert(&email, scopes.clone(), &chrono::Utc::now().to_rfc3339());
            registry.save(&config)?;
            json!({
                "status": "success",
                "message": "Authentication successful. Encrypted credentials saved.",
                "account": email,
                "default": registry.default.as_deref() == Some(email.as_str()),
                "credentials_file": enc_path.display().to_string(),
            })
        }
    };
    output["encryption"] = json!("AES-256-GCM (key in OS keyring or local `.encryption_key`; set GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND=file for headless)");
    output["scopes"] = json!(scopes);
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
    Ok(())
}

/// Rejects a login whose Google account differs from the one requested.
fn check_login_email(
    requested: Option<&str>,
    actual: &str,
    registry: &crate::accounts::Registry,
) -> Result<(), GwsError> {
    match requested {
        Some(requested) if requested != actual => Err(GwsError::Account {
            reason: "accountMismatch".to_string(),
            message: format!(
                "Signed in as {actual}, but {requested} was requested. Nothing was saved. \
                 Pick {requested} in the browser, or omit --account to add {actual}."
            ),
            accounts: registry.emails(),
            default: registry.default.clone(),
        }),
        _ => Ok(()),
    }
}

/// Removes token and timezone caches in `dir` so they can't outlive the
/// credentials they were derived from.
fn clear_account_caches(dir: &Path) {
    for name in [
        "token_cache.json",
        "sa_token_cache.json",
        "account_timezone",
    ] {
        let path = dir.join(name);
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("Warning: failed to remove {}: {e}", path.display());
            }
        }
    }
}

/// Fetch the authenticated user's email from Google's userinfo endpoint.
async fn fetch_userinfo_email(access_token: &str) -> Option<String> {
    let client = match crate::client::build_client() {
        Ok(c) => c,
        Err(_) => return None,
    };
    let resp = client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    body.get("email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

async fn handle_export(unmasked: bool) -> Result<(), GwsError> {
    let enc_path = credential_store::encrypted_credentials_path();
    if !enc_path.exists() {
        return Err(GwsError::Auth(
            "No encrypted credentials found. Run 'gws auth login' first.".to_string(),
        ));
    }

    match credential_store::load_encrypted() {
        Ok(contents) => {
            if unmasked {
                println!("{contents}");
            } else if let Ok(mut creds) = serde_json::from_str::<serde_json::Value>(&contents) {
                if let Some(obj) = creds.as_object_mut() {
                    for key in ["client_secret", "refresh_token"] {
                        if let Some(val) = obj.get_mut(key) {
                            if let Some(s) = val.as_str() {
                                *val = json!(mask_secret(s));
                            }
                        }
                    }
                }
                println!("{}", serde_json::to_string_pretty(&creds).unwrap());
            } else {
                println!("{contents}");
            }
            Ok(())
        }
        Err(e) => Err(GwsError::Auth(format!(
            "Failed to decrypt credentials: {e}. May have been created on a different machine.",
        ))),
    }
}

/// Resolve OAuth client credentials from env vars or saved config file.
fn resolve_client_credentials() -> Result<(String, String, Option<String>), GwsError> {
    // 1. Try env vars first
    let env_id = std::env::var("GOOGLE_WORKSPACE_CLI_CLIENT_ID").ok();
    let env_secret = std::env::var("GOOGLE_WORKSPACE_CLI_CLIENT_SECRET").ok();

    if let (Some(id), Some(secret)) = (env_id, env_secret) {
        // Still try to load project_id from config file for the scope picker
        let project_id = crate::oauth_config::load_client_config()
            .ok()
            .map(|c| c.project_id);
        return Ok((id, secret, project_id));
    }

    // 2. Try saved client_secret.json
    match crate::oauth_config::load_client_config() {
        Ok(config) => Ok((
            config.client_id,
            config.client_secret,
            Some(config.project_id),
        )),
        Err(_) => Err(GwsError::Auth(
            format!(
                "No OAuth client configured.\n\n\
                 Either:\n  \
                   1. Run `gws auth setup` to configure a GCP project and OAuth client\n  \
                   2. Download client_secret.json from Google Cloud Console and save it to:\n     \
                      {}\n  \
                   3. Set env vars: GOOGLE_WORKSPACE_CLI_CLIENT_ID and GOOGLE_WORKSPACE_CLI_CLIENT_SECRET",
                crate::oauth_config::client_config_path().display()
            ),
        )),
    }
}

/// Resolve OAuth scopes: explicit flags > interactive picker > defaults.
///
/// When `services_filter` is `Some`, only scopes belonging to the specified
/// services are shown in the picker (or returned in non-interactive mode).
async fn resolve_scopes(
    scope_mode: ScopeMode,
    project_id: Option<&str>,
    services_filter: Option<&HashSet<String>>,
) -> Vec<String> {
    match scope_mode {
        ScopeMode::Custom(scopes) => return scopes,
        ScopeMode::Readonly => {
            let scopes: Vec<String> = READONLY_SCOPES.iter().map(|s| s.to_string()).collect();
            let mut result = filter_scopes_by_services(scopes, services_filter);
            augment_with_dynamic_scopes(&mut result, services_filter, true).await;
            return result;
        }
        ScopeMode::Full => {
            let scopes: Vec<String> = FULL_SCOPES.iter().map(|s| s.to_string()).collect();
            let mut result = filter_scopes_by_services(scopes, services_filter);
            augment_with_dynamic_scopes(&mut result, services_filter, false).await;
            return result;
        }
        ScopeMode::Default => {} // fall through to interactive picker / defaults
    }

    // Interactive scope picker when running in a TTY
    if !cfg!(test) && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        // If we have a project_id, use discovery-based scope picker (rich templates)
        if let Some(pid) = project_id {
            let enabled_apis = crate::setup::get_enabled_apis(pid);
            if !enabled_apis.is_empty() {
                let api_ids: Vec<String> = enabled_apis;
                let scopes = crate::setup::fetch_scopes_for_apis(&api_ids).await;
                if !scopes.is_empty() {
                    if let Some(selected) = run_discovery_scope_picker(&scopes, services_filter) {
                        return selected;
                    }
                }
            }
        }

        // Fallback: simple scope picker using static SCOPE_ENTRIES
        if let Some(selected) = run_simple_scope_picker(services_filter) {
            return selected;
        }
    }

    let defaults: Vec<String> = DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect();
    let mut result = filter_scopes_by_services(defaults, services_filter);
    augment_with_dynamic_scopes(&mut result, services_filter, false).await;
    result
}

/// Check if a scope URL belongs to one of the specified services.
///
/// Matching is done on the scope's short name (the part after
/// `https://www.googleapis.com/auth/`). A scope matches a service if its
/// short name equals the service or starts with `service.` (e.g. service
/// `drive` matches `drive`, `drive.readonly`, `drive.metadata.readonly`).
///
/// The `cloud-platform` scope always passes through since it's a
/// cross-service platform scope.
fn scope_matches_service(scope_url: &str, services: &HashSet<String>) -> bool {
    let short = scope_url
        .strip_prefix("https://www.googleapis.com/auth/")
        .unwrap_or(scope_url);

    // cloud-platform is a cross-service scope, always include
    if short == "cloud-platform" {
        return true;
    }

    let prefix = short.split('.').next().unwrap_or(short);

    services.iter().any(|svc| {
        let prefixes = map_service_to_scope_prefixes(svc);
        prefixes
            .iter()
            .any(|mapped| prefix == *mapped || short.starts_with(&format!("{mapped}.")))
    })
}

/// Map user-friendly service names to their OAuth scope prefixes.
/// Some services map to multiple scope prefixes (e.g. People API uses
/// both `contacts` and `directory` scopes).
fn map_service_to_scope_prefixes(service: &str) -> Vec<&str> {
    match service {
        "sheets" => vec!["spreadsheets"],
        "slides" => vec!["presentations"],
        "docs" => vec!["documents"],
        "people" => vec!["contacts", "directory"],
        s => vec![s],
    }
}

/// Remove restrictive scopes that are redundant when broader alternatives
/// are present. For example, `gmail.metadata` restricts query parameters
/// and is unnecessary when `gmail.modify`, `gmail.readonly`, or the full
/// `https://mail.google.com/` scope is already included.
///
/// This prevents Google from enforcing the restrictive scope's limitations
/// on the access token even though broader access was granted.
fn filter_redundant_restrictive_scopes(scopes: Vec<String>) -> Vec<String> {
    // Scopes that restrict API behavior when present in a token, even alongside
    // broader scopes. Each entry maps a restrictive scope to the broader scopes
    // that make it redundant. The restrictive scope is removed only if at least
    // one of its broader alternatives is already in the list.
    const RESTRICTIVE_SCOPES: &[(&str, &[&str])] = &[(
        "https://www.googleapis.com/auth/gmail.metadata",
        &[
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/gmail.readonly",
        ],
    )];

    let scope_set: std::collections::HashSet<String> = scopes.iter().cloned().collect();

    scopes
        .into_iter()
        .filter(|scope| {
            !RESTRICTIVE_SCOPES.iter().any(|(restrictive, broader)| {
                scope.as_str() == *restrictive && broader.iter().any(|b| scope_set.contains(*b))
            })
        })
        .collect()
}

/// Filter a list of scope URLs to only those matching the given services.
/// If no filter is provided, returns all scopes unchanged.
fn filter_scopes_by_services(
    scopes: Vec<String>,
    services_filter: Option<&HashSet<String>>,
) -> Vec<String> {
    match services_filter {
        Some(services) if !services.is_empty() => scopes
            .into_iter()
            .filter(|s| scope_matches_service(s, services))
            .collect(),
        _ => scopes,
    }
}

/// Check if a scope is subsumed by a broader scope in the list.
/// e.g. "drive.metadata" is subsumed by "drive", "calendar.events" by "calendar".
fn is_subsumed_scope(short: &str, all_shorts: &[&str]) -> bool {
    all_shorts.iter().any(|&other| {
        other != short
            && short.starts_with(other)
            && short.as_bytes().get(other.len()) == Some(&b'.')
    })
}

/// Determine if a discovered scope should be included in the "Recommended" template.
///
/// When a services filter is active, recommends all top-level (non-subsumed) scopes.
/// Otherwise, recommends only the curated `MINIMAL_SCOPES` list to stay under
/// the 25-scope limit for unverified apps and @gmail.com accounts.
///
/// Always excludes admin-only and Workspace-admin scopes.
fn is_recommended_scope(
    entry: &crate::setup::DiscoveredScope,
    all_shorts: &[&str],
    has_services_filter: bool,
) -> bool {
    if entry.short.starts_with("admin.") || is_workspace_admin_scope(&entry.url) {
        return false;
    }
    if has_services_filter {
        !is_subsumed_scope(&entry.short, all_shorts)
    } else {
        MINIMAL_SCOPES.contains(&entry.url.as_str())
    }
}

/// Run the rich discovery-based scope picker with templates.
fn run_discovery_scope_picker(
    relevant_scopes: &[crate::setup::DiscoveredScope],
    services_filter: Option<&HashSet<String>>,
) -> Option<Vec<String>> {
    use crate::setup::{ScopeClassification, PLATFORM_SCOPE};
    use crate::setup_tui::{PickerResult, SelectItem};

    let mut recommended_scopes = vec![];
    let mut readonly_scopes = vec![];
    let mut all_scopes = vec![];

    // Pre-filter scopes by services if a filter is specified
    let filtered_scopes: Vec<&crate::setup::DiscoveredScope> = relevant_scopes
        .iter()
        .filter(|e| {
            services_filter.is_none_or(|services| {
                services.is_empty() || scope_matches_service(&e.url, services)
            })
        })
        .collect();

    // Collect all short names for hierarchical dedup of Full Access template
    let all_shorts: Vec<&str> = filtered_scopes
        .iter()
        .filter(|e| !is_app_only_scope(&e.url))
        .map(|e| e.short.as_str())
        .collect();

    for entry in &filtered_scopes {
        // Skip app-only scopes that can't be used with user OAuth
        if is_app_only_scope(&entry.url) {
            continue;
        }

        if is_recommended_scope(entry, &all_shorts, services_filter.is_some()) {
            recommended_scopes.push(entry.short.to_string());
        }
        if entry.is_readonly {
            readonly_scopes.push(entry.short.to_string());
        }
        // For "Full Access": skip if a broader scope exists (hierarchical dedup)
        // e.g. "drive.metadata" is subsumed by "drive", "calendar.events" by "calendar"
        if !is_subsumed_scope(&entry.short, &all_shorts) {
            all_scopes.push(entry.short.to_string());
        }
    }

    let mut items: Vec<SelectItem> = vec![
        SelectItem {
            label: "✨ Recommended (Core Consumer Scopes)".to_string(),
            description: "Selects Drive, Gmail, Calendar, Docs, Sheets, Slides, and Tasks"
                .to_string(),
            selected: true,
            is_fixed: false,
            is_template: true,
            template_selects: recommended_scopes,
        },
        SelectItem {
            label: "🔒 Read Only".to_string(),
            description: "Selects only readonly scopes for enabled APIs".to_string(),
            selected: false,
            is_fixed: false,
            is_template: true,
            template_selects: readonly_scopes,
        },
        SelectItem {
            label: "⚠️ Full Access (All Scopes)".to_string(),
            description: "Selects ALL scopes, including restricted write scopes".to_string(),
            selected: false,
            is_fixed: false,
            is_template: true,
            template_selects: all_scopes,
        },
    ];
    let template_count = items.len();

    let mut valid_scope_indices: Vec<usize> = Vec::new();
    for (idx, entry) in filtered_scopes.iter().enumerate() {
        // Skip app-only scopes from the picker entirely
        if is_app_only_scope(&entry.url) {
            continue;
        }

        let (prefix, emoji) = match entry.classification {
            ScopeClassification::Restricted => ("RESTRICTED ", "⛔ "),
            ScopeClassification::Sensitive => ("SENSITIVE ", "⚠️  "),
            ScopeClassification::NonSensitive => ("", ""),
        };

        let desc_str = if entry.description.is_empty() {
            entry.url.clone()
        } else {
            entry.description.clone()
        };

        let description = if prefix.is_empty() {
            desc_str
        } else {
            format!("{}{}{}", emoji, prefix, desc_str)
        };

        let is_recommended = if entry.is_readonly {
            let superset = entry.url.strip_suffix(".readonly").unwrap_or(&entry.url);
            let superset_is_recommended = filtered_scopes
                .iter()
                .any(|s| s.url == superset && s.classification != ScopeClassification::Restricted);
            !superset_is_recommended
        } else {
            entry.classification != ScopeClassification::Restricted
        };

        items.push(SelectItem {
            label: entry.short.to_string(),
            description,
            selected: is_recommended,
            is_fixed: false,
            is_template: false,
            template_selects: vec![],
        });
        valid_scope_indices.push(idx);
    }

    match crate::setup_tui::run_picker(
        "Select OAuth scopes",
        "Space to toggle, Enter to confirm",
        items,
        true,
    ) {
        Ok(PickerResult::Confirmed(items)) => {
            let recommended = items.first().is_some_and(|i| i.selected);
            let readonly = items.get(1).is_some_and(|i| i.selected);
            let full = items.get(2).is_some_and(|i| i.selected);

            let mut selected: Vec<String> = Vec::new();

            if full && !recommended && !readonly {
                // Full Access: include all non-app-only scopes
                // (hierarchical dedup is applied in post-processing below)
                for entry in &filtered_scopes {
                    if is_app_only_scope(&entry.url) {
                        continue;
                    }
                    selected.push(entry.url.to_string());
                }
            } else if recommended && !full && !readonly {
                // Recommended: consumer scopes only (or top-level scopes if filtered).
                for entry in &filtered_scopes {
                    if is_app_only_scope(&entry.url) {
                        continue;
                    }
                    if is_recommended_scope(entry, &all_shorts, services_filter.is_some()) {
                        selected.push(entry.url.to_string());
                    }
                }
            } else if readonly && !full && !recommended {
                for entry in &filtered_scopes {
                    if is_app_only_scope(&entry.url) {
                        continue;
                    }
                    if entry.is_readonly {
                        selected.push(entry.url.to_string());
                    }
                }
            } else {
                for (i, item) in items.iter().enumerate().skip(template_count) {
                    if item.selected {
                        let picker_idx = i - template_count;
                        if let Some(&scope_idx) = valid_scope_indices.get(picker_idx) {
                            if let Some(entry) = filtered_scopes.get(scope_idx) {
                                selected.push(entry.url.to_string());
                            }
                        }
                    }
                }
            }

            // Always include cloud-platform scope
            if !selected.contains(&PLATFORM_SCOPE.to_string()) {
                selected.push(PLATFORM_SCOPE.to_string());
            }

            // Hierarchical dedup: if we have both a broad scope (e.g. `.../auth/drive`)
            // and a narrower scope (e.g. `.../auth/drive.metadata`, `.../auth/drive.readonly`),
            // drop the narrower one since the broad scope subsumes it.
            let prefix = "https://www.googleapis.com/auth/";
            let shorts: Vec<&str> = selected
                .iter()
                .filter_map(|s| s.strip_prefix(prefix))
                .collect();

            let mut deduplicated: Vec<String> = Vec::new();
            for scope in &selected {
                if let Some(short) = scope.strip_prefix(prefix) {
                    // Check if any OTHER selected scope is a prefix of this one
                    // e.g. "drive" is a prefix of "drive.metadata" → drop "drive.metadata"
                    let is_subsumed = shorts.iter().any(|&other| {
                        other != short
                            && short.starts_with(other)
                            && short.as_bytes().get(other.len()) == Some(&b'.')
                    });
                    if is_subsumed {
                        continue;
                    }
                }
                deduplicated.push(scope.clone());
            }

            if deduplicated.len() > 30 {
                eprintln!(
                    "⚠️  Warning: {} scopes selected. Unverified OAuth apps may fail with this many scopes.",
                    deduplicated.len()
                );
            }

            if deduplicated.is_empty() {
                None
            } else {
                Some(deduplicated)
            }
        }
        _ => None, // GoBack, Cancelled, or error
    }
}

/// Run the simple static scope picker (fallback when no project_id available).
fn run_simple_scope_picker(services_filter: Option<&HashSet<String>>) -> Option<Vec<String>> {
    use crate::setup_tui::{PickerResult, SelectItem};

    // Pre-filter SCOPE_ENTRIES by services if a filter is provided
    let entries: Vec<&ScopeEntry> = SCOPE_ENTRIES
        .iter()
        .filter(|entry| {
            services_filter.is_none_or(|services| {
                services.is_empty() || scope_matches_service(entry.scope, services)
            })
        })
        .collect();

    let items: Vec<SelectItem> = entries
        .iter()
        .map(|entry| SelectItem {
            label: entry.label.to_string(),
            description: entry.scope.to_string(),
            selected: true,
            is_fixed: false,
            is_template: false,
            template_selects: vec![],
        })
        .collect();

    match crate::setup_tui::run_picker(
        "Select OAuth scopes",
        "Space to toggle, 'a' to select all, Enter to confirm",
        items,
        true,
    ) {
        Ok(PickerResult::Confirmed(items)) => {
            let selected: Vec<String> = items
                .iter()
                .enumerate()
                .filter(|(_, item)| item.selected)
                .map(|(i, _)| entries[i].scope.to_string())
                .collect();
            if selected.is_empty() {
                None
            } else {
                Some(selected)
            }
        }
        _ => None,
    }
}

async fn handle_status() -> Result<(), GwsError> {
    let plain_path = plain_credentials_path();
    let enc_path = credential_store::encrypted_credentials_path();
    let token_cache = token_cache_path();

    let has_encrypted = enc_path.exists();
    let has_plain = plain_path.exists();
    let has_token_cache = token_cache.exists();

    let auth_method = if has_encrypted || has_plain {
        "oauth2"
    } else {
        "none"
    };

    let storage = if has_encrypted {
        "encrypted"
    } else if has_plain {
        "plaintext"
    } else {
        "none"
    };

    let mut output = json!({
        "auth_method": auth_method,
        "storage": storage,
        "keyring_backend": credential_store::active_backend_name(),
        "encrypted_credentials": enc_path.display().to_string(),
        "encrypted_credentials_exists": has_encrypted,
        "plain_credentials": plain_path.display().to_string(),
        "plain_credentials_exists": has_plain,
        "token_cache_exists": has_token_cache,
    });
    if let Some(account) = crate::accounts::active_account() {
        output["account"] = json!(account.email);
    }

    // Show client config (client_secret.json) status
    let config_path = crate::oauth_config::client_config_path();
    let has_config = config_path.exists();
    output["client_config"] = json!(config_path.display().to_string());
    output["client_config_exists"] = json!(has_config);

    if has_config {
        match crate::oauth_config::load_client_config() {
            Ok(config) => {
                output["project_id"] = json!(config.project_id);
                let masked_id = if config.client_id.len() > 12 {
                    format!(
                        "{}...{}",
                        &config.client_id[..8],
                        &config.client_id[config.client_id.len() - 4..]
                    )
                } else {
                    config.client_id.clone()
                };
                output["config_client_id"] = json!(masked_id);
            }
            Err(e) => {
                output["client_config_error"] = json!(e.to_string());
            }
        }
    }

    // Show credential source by attempting actual resolution
    let has_token_env = std::env::var("GOOGLE_WORKSPACE_CLI_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .is_some();

    let credential_source = if has_token_env {
        output["token_env_var"] = json!(true);
        "token_env_var"
    } else {
        match resolve_client_credentials() {
            Ok((_, _, _)) => {
                let has_env_id = std::env::var("GOOGLE_WORKSPACE_CLI_CLIENT_ID").is_ok();
                let has_env_secret = std::env::var("GOOGLE_WORKSPACE_CLI_CLIENT_SECRET").is_ok();
                if has_env_id && has_env_secret {
                    "environment_variables"
                } else {
                    "client_secret.json"
                }
            }
            Err(_) => "none",
        }
    };
    output["credential_source"] = json!(credential_source);

    // Try to read and show masked info from encrypted credentials
    // Skip real credential/network access in test builds
    if !cfg!(test) {
        if has_encrypted {
            match credential_store::load_encrypted() {
                Ok(contents) => {
                    if let Ok(creds) = serde_json::from_str::<serde_json::Value>(&contents) {
                        if let Some(client_id) = creds.get("client_id").and_then(|v| v.as_str()) {
                            let masked = if client_id.len() > 12 {
                                format!(
                                    "{}...{}",
                                    &client_id[..8],
                                    &client_id[client_id.len() - 4..]
                                )
                            } else {
                                client_id.to_string()
                            };
                            output["client_id"] = json!(masked);
                        }
                        output["has_refresh_token"] = json!(creds
                            .get("refresh_token")
                            .and_then(|v| v.as_str())
                            .is_some());
                    }
                    output["encryption_valid"] = json!(true);
                }
                Err(_) => {
                    output["encryption_valid"] = json!(false);
                    output["encryption_error"] =
                        json!("Could not decrypt. May have been created on a different machine.");
                }
            }
        } else if has_plain {
            match tokio::fs::read_to_string(&plain_path).await {
                Ok(contents) => {
                    if let Ok(creds) = serde_json::from_str::<serde_json::Value>(&contents) {
                        if let Some(client_id) = creds.get("client_id").and_then(|v| v.as_str()) {
                            let masked = if client_id.len() > 12 {
                                format!(
                                    "{}...{}",
                                    &client_id[..8],
                                    &client_id[client_id.len() - 4..]
                                )
                            } else {
                                client_id.to_string()
                            };
                            output["client_id"] = json!(masked);
                        }
                        output["has_refresh_token"] = json!(creds.get("refresh_token").is_some());
                    }
                }
                Err(_) => {
                    output["credentials_readable"] = json!(false);
                }
            }
        }
    } // end !cfg!(test)

    // If we have credentials, try to get live info (user, scopes, APIs)
    // Skip all network calls and subprocess spawning in test builds
    if !cfg!(test) {
        let creds_json_str = if has_encrypted {
            credential_store::load_encrypted().ok()
        } else if has_plain {
            tokio::fs::read_to_string(&plain_path).await.ok()
        } else {
            None
        };

        if let Some(creds_str) = creds_json_str {
            if let Ok(creds) = serde_json::from_str::<serde_json::Value>(&creds_str) {
                let client_id = creds.get("client_id").and_then(|v| v.as_str());
                let client_secret = creds.get("client_secret").and_then(|v| v.as_str());
                let refresh_token = creds.get("refresh_token").and_then(|v| v.as_str());

                if let (Some(cid), Some(csec), Some(rt)) = (client_id, client_secret, refresh_token)
                {
                    // Exchange refresh token for access token
                    if let Ok(http_client) = crate::client::shared_client() {
                        let token_resp = http_client
                            .post("https://oauth2.googleapis.com/token")
                            .form(&[
                                ("client_id", cid),
                                ("client_secret", csec),
                                ("refresh_token", rt),
                                ("grant_type", "refresh_token"),
                            ])
                            .send()
                            .await;

                        if let Ok(resp) = token_resp {
                            if let Ok(token_json) = resp.json::<serde_json::Value>().await {
                                if let Some(access_token) =
                                    token_json.get("access_token").and_then(|v| v.as_str())
                                {
                                    output["token_valid"] = json!(true);

                                    // Get user info
                                    if let Ok(user_resp) = http_client
                                        .get("https://www.googleapis.com/oauth2/v1/userinfo")
                                        .bearer_auth(access_token)
                                        .send()
                                        .await
                                    {
                                        if let Ok(user_json) =
                                            user_resp.json::<serde_json::Value>().await
                                        {
                                            if let Some(email) =
                                                user_json.get("email").and_then(|v| v.as_str())
                                            {
                                                output["user"] = json!(email);
                                            }
                                        }
                                    }

                                    // Get granted scopes via tokeninfo
                                    let tokeninfo_url = format!(
                                        "https://oauth2.googleapis.com/tokeninfo?access_token={}",
                                        access_token
                                    );
                                    if let Ok(info_resp) =
                                        http_client.get(&tokeninfo_url).send().await
                                    {
                                        if let Ok(info_json) =
                                            info_resp.json::<serde_json::Value>().await
                                        {
                                            if let Some(scope_str) =
                                                info_json.get("scope").and_then(|v| v.as_str())
                                            {
                                                let scopes: Vec<&str> =
                                                    scope_str.split(' ').collect();
                                                output["scopes"] = json!(scopes);
                                                output["scope_count"] = json!(scopes.len());
                                            }
                                        }
                                    }
                                } else {
                                    output["token_valid"] = json!(false);
                                    if let Some(err) =
                                        token_json.get("error_description").and_then(|v| v.as_str())
                                    {
                                        output["token_error"] = json!(err);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Show enabled APIs if we have a project_id
        if let Some(pid) = output.get("project_id").and_then(|v| v.as_str()) {
            let enabled = crate::setup::get_enabled_apis(pid);
            if !enabled.is_empty() {
                output["enabled_apis"] = json!(enabled);
                output["enabled_api_count"] = json!(enabled.len());
            }
        }
    } // end !cfg!(test)

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
    Ok(())
}

async fn handle_logout(revoke: bool) -> Result<(), GwsError> {
    let plain_path = plain_credentials_path();
    let enc_path = credential_store::encrypted_credentials_path();
    let token_cache = token_cache_path();
    let sa_token_cache = crate::accounts::credential_dir().join("sa_token_cache.json");

    let revoked = if revoke {
        Some(revoke_saved_refresh_token(&enc_path, &plain_path).await)
    } else {
        None
    };

    let mut removed = Vec::new();

    for path in [&enc_path, &plain_path, &token_cache, &sa_token_cache] {
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| {
                GwsError::Validation(format!("Failed to remove {}: {e}", path.display()))
            })?;
            removed.push(path.display().to_string());
        }
    }

    // Invalidate cached account timezone (may belong to old account)
    crate::timezone::invalidate_cache();

    // A registered account is removed entirely: its directory (including a
    // per-account OAuth client) and its registry entry.
    let mut account_removed = None;
    if let Some(account) = crate::accounts::active_account() {
        let client = account.dir.join(crate::oauth_config::CLIENT_SECRET_FILE);
        if client.exists() {
            std::fs::remove_file(&client).map_err(|e| {
                GwsError::Validation(format!("Failed to remove {}: {e}", client.display()))
            })?;
            removed.push(client.display().to_string());
        }
        // Only removes the directory if nothing unexpected is left in it.
        let _ = std::fs::remove_dir(&account.dir);

        let config = config_dir();
        if let Some(mut registry) = crate::accounts::Registry::load(&config)? {
            registry.remove(&account.email);
            registry.save(&config)?;
        }
        account_removed = Some(account.email.clone());
    }

    let mut output = if removed.is_empty() {
        json!({
            "status": "success",
            "message": "No credentials found to remove.",
        })
    } else {
        json!({
            "status": "success",
            "message": "Logged out. All credentials and token caches removed.",
            "removed": removed,
        })
    };
    if let Some(email) = account_removed {
        output["account"] = json!(email);
    }
    match revoked {
        Some(Ok(())) => output["revoked"] = json!(true),
        Some(Err(e)) => {
            eprintln!("Warning: could not revoke the refresh token at Google: {e}");
            output["revoked"] = json!(false);
        }
        None => {}
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
    Ok(())
}

/// Revokes the saved refresh token at Google, so the grant stops working even
/// if a copy of the credentials survives elsewhere.
async fn revoke_saved_refresh_token(enc_path: &Path, plain_path: &Path) -> Result<(), String> {
    let creds = if enc_path.exists() {
        credential_store::load_encrypted_from_path(enc_path).map_err(|e| format!("{e:#}"))?
    } else if plain_path.exists() {
        std::fs::read_to_string(plain_path).map_err(|e| e.to_string())?
    } else {
        return Err("no saved credentials".to_string());
    };
    let refresh_token = serde_json::from_str::<serde_json::Value>(&creds)
        .ok()
        .and_then(|v| v.get("refresh_token")?.as_str().map(str::to_string))
        .ok_or_else(|| "saved credentials have no refresh token".to_string())?;
    let client = crate::client::shared_client().map_err(|e| e.to_string())?;
    let resp = client
        .post("https://oauth2.googleapis.com/revoke")
        .form(&[("token", refresh_token.as_str())])
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("revoke endpoint returned {}", resp.status()))
    }
}

/// Resolves the account an `auth` subcommand acts on.
fn select_account_for_auth(access: crate::accounts::Access) -> Result<(), GwsError> {
    crate::accounts::select(access, false).map(|_| ())
}

fn handle_list() -> Result<(), GwsError> {
    let config = config_dir();
    let output = match crate::accounts::Registry::load(&config)? {
        Some(registry) => {
            let accounts: Vec<serde_json::Value> = registry
                .accounts
                .iter()
                .map(|(email, meta)| {
                    let own_client = crate::accounts::account_dir(&config, email)
                        .join(crate::oauth_config::CLIENT_SECRET_FILE)
                        .exists();
                    json!({
                        "email": email,
                        "default": registry.default.as_deref() == Some(email.as_str()),
                        "client": if own_client { "account" } else { "shared" },
                        "scopes": meta.scopes,
                        "added": meta.added,
                    })
                })
                .collect();
            json!({ "default": registry.default, "accounts": accounts })
        }
        None => json!({
            "default": null,
            "accounts": [],
            "message": format!(
                "{} has no account registry (single-account mode). Run `gws auth login` or `gws auth import --from <dir>`.",
                config.display()
            ),
        }),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
    Ok(())
}

fn handle_default(raw_email: &str) -> Result<(), GwsError> {
    let email = crate::accounts::normalize_email(raw_email)?;
    let config = config_dir();
    let mut registry = crate::accounts::Registry::load(&config)?.ok_or_else(|| {
        GwsError::Validation(format!(
            "{} has no account registry. Run `gws auth login` first.",
            config.display()
        ))
    })?;
    registry.set_default(&email)?;
    registry.save(&config)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({ "status": "success", "default": email }))
            .unwrap_or_default()
    );
    Ok(())
}

/// Scopes granted to an access token, from Google's tokeninfo endpoint.
async fn fetch_granted_scopes(access_token: &str) -> Vec<String> {
    let Ok(client) = crate::client::shared_client() else {
        return Vec::new();
    };
    let Ok(resp) = client
        .get("https://oauth2.googleapis.com/tokeninfo")
        .query(&[("access_token", access_token)])
        .send()
        .await
    else {
        return Vec::new();
    };
    resp.json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|v| v.get("scope")?.as_str().map(str::to_string))
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Reads the client ID from an OAuth client file, if it parses.
fn client_id_of(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let file: crate::oauth_config::ClientSecretFile = serde_json::from_str(&text).ok()?;
    Some(file.installed.client_id)
}

/// OAuth user credentials read from a config directory being imported.
#[derive(Debug)]
struct ImportSource {
    creds_json: String,
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

/// Decrypts `src/credentials.enc` with that directory's key: its
/// `.encryption_key` file for the file backend, otherwise this process's key.
fn read_import_source(src: &Path, file_backend: bool) -> Result<ImportSource, GwsError> {
    let enc = src.join("credentials.enc");
    let data = std::fs::read(&enc)
        .map_err(|e| GwsError::Validation(format!("Cannot read {}: {e}", enc.display())))?;
    let plaintext = if file_backend {
        let key_path = src.join(".encryption_key");
        let key = credential_store::load_key_file(&key_path).ok_or_else(|| {
            GwsError::Validation(format!("No valid encryption key at {}", key_path.display()))
        })?;
        credential_store::decrypt_with_key(&key, &data)
    } else {
        credential_store::decrypt(&data)
    }
    .map_err(|e| {
        GwsError::Auth(format!(
            "Could not decrypt {} ({e:#}). If that directory used the file backend, pass --keyring-backend file.",
            enc.display()
        ))
    })?;
    let creds_json = String::from_utf8(plaintext)
        .map_err(|_| GwsError::Validation(format!("{} is not valid UTF-8", enc.display())))?;
    let creds: serde_json::Value = serde_json::from_str(&creds_json)
        .map_err(|_| GwsError::Validation(format!("{} does not contain JSON", enc.display())))?;
    let field = |name: &str| creds.get(name).and_then(|v| v.as_str()).map(str::to_string);
    match (
        field("client_id"),
        field("client_secret"),
        field("refresh_token"),
    ) {
        (Some(client_id), Some(client_secret), Some(refresh_token)) => Ok(ImportSource {
            creds_json,
            client_id,
            client_secret,
            refresh_token,
        }),
        _ => Err(GwsError::Validation(format!(
            "{} does not hold OAuth user credentials (service accounts can't be imported)",
            enc.display()
        ))),
    }
}

/// Imports the single-account credentials of another config directory (or of
/// this one, converting it to the account registry).
///
/// `from` is deliberately not restricted to the current directory: it points
/// at another gws config directory (e.g. `~/.config/gws-work`), and only the
/// gws-written `credentials.enc`, `.encryption_key` and `client_secret.json`
/// are read from it. Nothing in it is modified, except when importing the
/// config directory into itself.
async fn handle_import(from: &str, file_backend: bool) -> Result<(), GwsError> {
    crate::validate::reject_dangerous_chars(from, "--from")?;
    let src = std::fs::canonicalize(from)
        .map_err(|e| GwsError::Validation(format!("Cannot open {from}: {e}")))?;
    let config = config_dir();
    std::fs::create_dir_all(&config)
        .map_err(|e| GwsError::Validation(format!("Failed to create config directory: {e}")))?;
    let in_place = std::fs::canonicalize(&config).ok().as_deref() == Some(src.as_path());

    // 1. Decrypt the source credentials with the source's key.
    let ImportSource {
        creds_json: creds_str,
        client_id,
        client_secret,
        refresh_token,
    } = read_import_source(&src, file_backend)?;

    // 2. Find out whose credentials these are, and what they may do.
    let access_token =
        crate::auth::refresh_token_with_reqwest(&client_id, &client_secret, &refresh_token)
            .await
            .map_err(|e| GwsError::Auth(format!("The imported credentials don't work: {e:#}")))?;
    let email = fetch_userinfo_email(&access_token)
        .await
        .ok_or_else(|| GwsError::Auth("Could not determine the account's email".to_string()))
        .and_then(|e| crate::accounts::normalize_email(&e))?;
    let scopes = fetch_granted_scopes(&access_token).await;

    let mut registry = crate::accounts::Registry::load(&config)?.unwrap_or_default();
    if registry.accounts.contains_key(&email) {
        return Err(GwsError::Account {
            reason: "accountExists".to_string(),
            message: format!(
                "{email} is already configured. Run `gws auth logout --account {email}` first to re-import it."
            ),
            accounts: registry.emails(),
            default: registry.default.clone(),
        });
    }

    // 3. Store them as an account, encrypted with this config's key.
    let dir = crate::accounts::account_dir(&config, &email);
    crate::accounts::create_private_dir(&dir)?;
    let enc_path = credential_store::save_encrypted_to(&dir.join("credentials.enc"), &creds_str)
        .map_err(|e| GwsError::Auth(format!("Failed to encrypt credentials: {e}")))?;

    // Keep the source's OAuth client for future logins if it isn't the shared one.
    let shared = crate::oauth_config::shared_client_config_path();
    let src_client = src.join(crate::oauth_config::CLIENT_SECRET_FILE);
    let mut own_client = false;
    if !in_place && src_client.exists() && client_id_of(&src_client) != client_id_of(&shared) {
        let text = std::fs::read(&src_client).map_err(|e| {
            GwsError::Validation(format!("Cannot read {}: {e}", src_client.display()))
        })?;
        let path = dir.join(crate::oauth_config::CLIENT_SECRET_FILE);
        crate::fs_util::atomic_write(&path, &text).map_err(|e| {
            GwsError::Validation(format!("Failed to write {}: {e}", path.display()))
        })?;
        own_client = true;
    }

    registry.upsert(&email, scopes.clone(), &chrono::Utc::now().to_rfc3339());
    registry.save(&config)?;

    // 4. Importing a config directory into itself: retire its single-account
    //    files so nothing is left that looks like the active credentials.
    let mut retired = Vec::new();
    if in_place {
        let stamp = chrono::Local::now().format("%Y%m%d%H%M%S");
        for name in ["credentials.enc", "token_cache.json", "sa_token_cache.json"] {
            let path = config.join(name);
            if path.exists() {
                let target = config.join(format!("{name}.imported-{stamp}"));
                std::fs::rename(&path, &target).map_err(|e| {
                    GwsError::Validation(format!("Failed to rename {}: {e}", path.display()))
                })?;
                retired.push(target.display().to_string());
            }
        }
        let _ = std::fs::remove_file(config.join("account_timezone"));
    }

    let output = json!({
        "status": "success",
        "account": email,
        "default": registry.default.as_deref() == Some(email.as_str()),
        "imported_from": src.display().to_string(),
        "credentials_file": enc_path.display().to_string(),
        "client": if own_client { "account" } else { "shared" },
        "scope_count": scopes.len(),
        "retired": retired,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
    Ok(())
}

/// Extract refresh_token from yup-oauth2 v12 token cache.
///
/// Supports two formats:
/// 1. Array format (yup-oauth2 default file storage):
///    [{"scopes":[...], "token":{"access_token":..., "refresh_token":...}}]
/// 2. Object/HashMap format (EncryptedTokenStorage serialization):
///    {"scope_key": {"access_token":..., "refresh_token":..., ...}}
pub fn extract_refresh_token(token_data: &str) -> Option<String> {
    let cache: serde_json::Value = serde_json::from_str(token_data).ok()?;

    // Format 1: array of {scopes, token} entries
    if let Some(arr) = cache.as_array() {
        let result = arr.iter().find_map(|entry| {
            entry
                .get("token")
                .and_then(|t| t.get("refresh_token"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });
        if result.is_some() {
            return result;
        }
    }

    // Format 2: HashMap<String, TokenInfo> — values are TokenInfo structs
    if let Some(obj) = cache.as_object() {
        for value in obj.values() {
            if let Some(rt) = value.get("refresh_token").and_then(|v| v.as_str()) {
                return Some(rt.to_string());
            }
        }
    }

    None
}

/// Parse --scopes or --readonly from args, falling back to DEFAULT_SCOPES.
/// Scope entry with a human-readable label for the TUI picker.
struct ScopeEntry {
    scope: &'static str,
    label: &'static str,
}

const SCOPE_ENTRIES: &[ScopeEntry] = &[
    ScopeEntry {
        scope: "https://www.googleapis.com/auth/drive",
        label: "Google Drive",
    },
    ScopeEntry {
        scope: "https://www.googleapis.com/auth/spreadsheets",
        label: "Google Sheets",
    },
    ScopeEntry {
        scope: "https://www.googleapis.com/auth/gmail.modify",
        label: "Gmail",
    },
    ScopeEntry {
        scope: "https://www.googleapis.com/auth/calendar",
        label: "Google Calendar",
    },
    ScopeEntry {
        scope: "https://www.googleapis.com/auth/documents",
        label: "Google Docs",
    },
    ScopeEntry {
        scope: "https://www.googleapis.com/auth/presentations",
        label: "Google Slides",
    },
    ScopeEntry {
        scope: "https://www.googleapis.com/auth/tasks",
        label: "Google Tasks",
    },
    ScopeEntry {
        scope: "https://www.googleapis.com/auth/pubsub",
        label: "Cloud Pub/Sub",
    },
    ScopeEntry {
        scope: "https://www.googleapis.com/auth/cloud-platform",
        label: "Cloud Platform",
    },
];

// (parse_scopes removed — replaced by resolve_scopes above)

/// Helper: check if a scope can't be used with user OAuth consent flow
/// (requires a Chat app or service account).
fn is_app_only_scope(url: &str) -> bool {
    url.contains("/auth/chat.app.")
        || url.contains("/auth/chat.bot")
        || url.contains("/auth/chat.import")
        || url.contains("/auth/keep")
        || url.contains("/auth/apps.alerts")
}

/// Helper: check if a scope requires Workspace domain admin access and therefore
/// cannot be granted to personal `@gmail.com` accounts via standard user OAuth.
///
/// These scopes are valid in Workspace environments with a domain admin, but
/// Google returns `400 invalid_scope` when requested by personal accounts.
/// They are excluded from the "Recommended" preset to avoid login failures.
///
/// Affected scope families:
/// - `apps.*`            — Alert Center, Groups Settings, Licensing, Reseller
/// - `cloud-identity.*`  — Cloud Identity: devices, groups, inbound SSO, policies
/// - `ediscovery`        — Google Vault
/// - `directory.readonly`— Admin SDK Directory (read-only)
/// - `groups`            — Groups Management
fn is_workspace_admin_scope(url: &str) -> bool {
    let short = url
        .strip_prefix("https://www.googleapis.com/auth/")
        .unwrap_or(url);
    short.starts_with("apps.")
        || short.starts_with("cloud-identity.")
        || short.starts_with("chat.admin.")
        || short.starts_with("classroom.")
        || short == "ediscovery"
        || short == "directory.readonly"
        || short == "groups"
}

/// Identify services from the filter that have no matching scopes in the result.
///
/// `cloud-platform` is a cross-service scope and does not count as a match
/// for any specific service.
fn find_unmatched_services(scopes: &[String], services: &HashSet<String>) -> HashSet<String> {
    let mut matched_services = HashSet::new();

    for scope in scopes.iter().filter(|s| !s.ends_with("/cloud-platform")) {
        let short = match scope.strip_prefix("https://www.googleapis.com/auth/") {
            Some(s) => s,
            None => continue,
        };
        let prefix = short.split('.').next().unwrap_or(short);

        for service in services {
            if matched_services.contains(service) {
                continue;
            }
            let prefixes = map_service_to_scope_prefixes(service);
            if prefixes
                .iter()
                .any(|mapped| prefix == *mapped || short.starts_with(&format!("{mapped}.")))
            {
                matched_services.insert(service.clone());
            }
        }
    }

    services.difference(&matched_services).cloned().collect()
}

/// Extract OAuth scope URLs from a Discovery document.
///
/// Filters out app-only scopes (e.g. `chat.bot`, `chat.app.*`) and optionally
/// restricts to `.readonly` scopes when `readonly_only` is true.
fn extract_scopes_from_doc(
    doc: &crate::discovery::RestDescription,
    readonly_only: bool,
) -> Vec<String> {
    let scopes = match doc
        .auth
        .as_ref()
        .and_then(|a| a.oauth2.as_ref())
        .and_then(|o| o.scopes.as_ref())
    {
        Some(s) => s,
        None => return Vec::new(),
    };
    scopes
        .keys()
        .filter(|url| !is_app_only_scope(url))
        .filter(|url| !readonly_only || url.ends_with(".readonly"))
        .cloned()
        .collect()
}

/// Fetch scopes from Discovery docs for services that had no matching scopes
/// in the static lists. Failures are silently skipped (graceful degradation).
async fn fetch_scopes_for_unmatched_services(
    services: &HashSet<String>,
    readonly_only: bool,
) -> Vec<String> {
    let futures: Vec<_> = services
        .iter()
        .filter_map(|svc| {
            let (api_name, version) = crate::services::resolve_service(svc).ok()?;
            Some(async move {
                crate::discovery::fetch_discovery_document(&api_name, &version)
                    .await
                    .ok()
                    .map(|doc| extract_scopes_from_doc(&doc, readonly_only))
            })
        })
        .collect();

    let mut result: Vec<String> = futures_util::future::join_all(futures)
        .await
        .into_iter()
        .flatten()
        .flatten()
        .collect();
    result.sort();
    result.dedup();
    result
}

/// If a services filter is active and some services have no matching scopes in
/// the static result, dynamically fetch their scopes from Discovery docs.
async fn augment_with_dynamic_scopes(
    result: &mut Vec<String>,
    services_filter: Option<&HashSet<String>>,
    readonly_only: bool,
) {
    if let Some(services) = services_filter {
        let missing = find_unmatched_services(result, services);
        if !missing.is_empty() {
            let dynamic = fetch_scopes_for_unmatched_services(&missing, readonly_only).await;
            for scope in dynamic {
                if !result.contains(&scope) {
                    result.push(scope);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to run resolve_scopes in tests (async).
    fn run_resolve_scopes(scope_mode: ScopeMode, project_id: Option<&str>) -> Vec<String> {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(resolve_scopes(scope_mode, project_id, None))
    }

    /// Helper to run resolve_scopes with a services filter.
    fn run_resolve_scopes_with_services(
        scope_mode: ScopeMode,
        project_id: Option<&str>,
        services: &[&str],
    ) -> Vec<String> {
        let filter: HashSet<String> = services.iter().map(|s| s.to_string()).collect();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(resolve_scopes(scope_mode, project_id, Some(&filter)))
    }

    #[test]
    fn resolve_scopes_returns_defaults_when_no_flag() {
        let scopes = run_resolve_scopes(ScopeMode::Default, None);
        assert_eq!(scopes.len(), DEFAULT_SCOPES.len());
        assert_eq!(scopes[0], "https://www.googleapis.com/auth/drive");
    }

    #[test]
    fn resolve_scopes_returns_custom_scopes() {
        let scopes = run_resolve_scopes(
            ScopeMode::Custom(vec![
                "https://www.googleapis.com/auth/drive.readonly".to_string()
            ]),
            None,
        );
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], "https://www.googleapis.com/auth/drive.readonly");
    }

    #[test]
    fn resolve_scopes_handles_multiple_custom() {
        let scopes = run_resolve_scopes(
            ScopeMode::Custom(vec![
                "https://www.googleapis.com/auth/drive".to_string(),
                "https://www.googleapis.com/auth/gmail.readonly".to_string(),
            ]),
            None,
        );
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0], "https://www.googleapis.com/auth/drive");
        assert_eq!(scopes[1], "https://www.googleapis.com/auth/gmail.readonly");
    }

    #[test]
    fn resolve_scopes_readonly_returns_readonly_scopes() {
        let scopes = run_resolve_scopes(ScopeMode::Readonly, None);
        assert_eq!(scopes.len(), READONLY_SCOPES.len());
        for scope in &scopes {
            assert!(
                scope.ends_with(".readonly"),
                "Expected readonly scope, got: {scope}"
            );
        }
    }

    #[test]
    fn resolve_scopes_full_returns_full_scopes() {
        let scopes = run_resolve_scopes(ScopeMode::Full, None);
        assert_eq!(scopes.len(), FULL_SCOPES.len());
    }

    #[test]
    #[serial_test::serial]
    fn resolve_client_credentials_from_env_vars() {
        unsafe {
            std::env::set_var("GOOGLE_WORKSPACE_CLI_CLIENT_ID", "test-id");
            std::env::set_var("GOOGLE_WORKSPACE_CLI_CLIENT_SECRET", "test-secret");
        }
        let result = resolve_client_credentials();
        unsafe {
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CLIENT_ID");
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CLIENT_SECRET");
        }
        let (id, secret, _project_id) = result.unwrap();
        assert_eq!(id, "test-id");
        assert_eq!(secret, "test-secret");
        // project_id may be Some if client_secret.json exists on the machine
    }

    #[test]
    #[serial_test::serial]
    fn resolve_client_credentials_missing_env_vars_uses_config() {
        unsafe {
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CLIENT_ID");
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CLIENT_SECRET");
        }
        // Result depends on whether client_secret.json exists on the machine
        let result = resolve_client_credentials();
        if crate::oauth_config::client_config_path().exists() {
            assert!(
                result.is_ok(),
                "Should succeed when client_secret.json exists"
            );
        } else {
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("No OAuth client configured"));
        }
    }

    #[test]
    #[serial_test::serial]
    fn config_dir_returns_gws_subdir() {
        let path = config_dir();
        assert!(path.ends_with("gws"));
    }

    #[test]
    fn config_dir_primary_uses_dot_config() {
        // The primary (non-test) path should be ~/.config/gws.
        // We can't easily test the real function without env override,
        // but we verify the building blocks: home_dir + .config + gws.
        let primary = dirs::home_dir().unwrap().join(".config").join("gws");
        assert!(primary.ends_with(".config/gws") || primary.ends_with(r".config\gws"));
    }

    #[test]
    #[serial_test::serial]
    fn config_dir_fallback_to_legacy() {
        // When GOOGLE_WORKSPACE_CLI_CONFIG_DIR points to a legacy-style dir,
        // config_dir() should return it (simulating the test env override).
        let dir = tempfile::tempdir().unwrap();
        let legacy = dir.path().join("legacy_gws");
        std::fs::create_dir_all(&legacy).unwrap();

        unsafe {
            std::env::set_var("GOOGLE_WORKSPACE_CLI_CONFIG_DIR", legacy.to_str().unwrap());
        }
        let path = config_dir();
        assert_eq!(path, legacy);
        unsafe {
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CONFIG_DIR");
        }
    }

    #[test]
    #[serial_test::serial]
    fn plain_credentials_path_defaults_to_config_dir() {
        // Without env var, should be in config dir
        unsafe {
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE");
        }
        let path = plain_credentials_path();
        assert!(path.ends_with("credentials.json"));
        assert!(path.starts_with(config_dir()));
    }

    #[test]
    #[serial_test::serial]
    fn plain_credentials_path_respects_env_var() {
        unsafe {
            std::env::set_var(
                "GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE",
                "/tmp/test-creds.json",
            );
        }
        let path = plain_credentials_path();
        assert_eq!(path, PathBuf::from("/tmp/test-creds.json"));
        unsafe {
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE");
        }
    }

    #[test]
    fn token_cache_path_is_in_config_dir() {
        let path = token_cache_path();
        assert!(path.ends_with("token_cache.json"));
        assert!(path.starts_with(config_dir()));
    }

    #[tokio::test]
    async fn handle_auth_command_empty_args_prints_usage() {
        let args: Vec<String> = vec![];
        let result = handle_auth_command(&args).await;
        // Empty args now prints usage and returns Ok
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_auth_command_help_flag_returns_ok() {
        let args = vec!["--help".to_string()];
        let result = handle_auth_command(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_auth_command_help_short_flag_returns_ok() {
        let args = vec!["-h".to_string()];
        let result = handle_auth_command(&args).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handle_auth_command_invalid_subcommand() {
        let args = vec!["frobnicate".to_string()];
        let result = handle_auth_command(&args).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            GwsError::Validation(msg) => assert!(msg.contains("frobnicate")),
            other => panic!("Expected Validation error, got: {other:?}"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn resolve_credentials_fails_without_env_vars_or_config() {
        unsafe {
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CLIENT_ID");
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CLIENT_SECRET");
        }
        // When no env vars AND no client_secret.json on disk, should fail
        let result = resolve_client_credentials();
        if !crate::oauth_config::client_config_path().exists() {
            assert!(result.is_err());
            match result.unwrap_err() {
                GwsError::Auth(msg) => assert!(msg.contains("No OAuth client configured")),
                other => panic!("Expected Auth error, got: {other:?}"),
            }
        }
        // If client_secret.json exists on the dev machine, credentials resolve
        // successfully — that's correct behavior, not a test failure.
    }

    #[test]
    #[serial_test::serial]
    fn resolve_credentials_uses_env_vars_when_present() {
        unsafe {
            std::env::set_var("GOOGLE_WORKSPACE_CLI_CLIENT_ID", "test-id");
            std::env::set_var("GOOGLE_WORKSPACE_CLI_CLIENT_SECRET", "test-secret");
        }

        let result = resolve_client_credentials();

        // Clean up immediately
        unsafe {
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CLIENT_ID");
            std::env::remove_var("GOOGLE_WORKSPACE_CLI_CLIENT_SECRET");
        }

        let (id, secret, _) = result.unwrap();
        assert_eq!(id, "test-id");
        assert_eq!(secret, "test-secret");
    }

    #[tokio::test]
    async fn handle_status_succeeds_without_credentials() {
        // status should always succeed and report "none"
        let args = vec!["status".to_string()];
        let result = handle_auth_command(&args).await;
        assert!(result.is_ok());
    }

    #[test]
    fn credential_store_save_load_round_trip() {
        // Use encrypt/decrypt directly to avoid writing to the real config dir
        let json = r#"{"client_id":"test","client_secret":"secret","refresh_token":"tok"}"#;
        let encrypted = credential_store::encrypt(json.as_bytes()).expect("encrypt should succeed");
        let decrypted = credential_store::decrypt(&encrypted).expect("decrypt should succeed");
        assert_eq!(String::from_utf8(decrypted).unwrap(), json);
    }

    #[test]
    fn extract_refresh_token_from_yup_oauth2_format() {
        // Actual format produced by yup-oauth2 v12
        let data = r#"[{"scopes":["https://www.googleapis.com/auth/drive"],"token":{"access_token":"ya29.test","refresh_token":"1//test-refresh-token","expires_at":[2026,43,19,44,15,0,0,0,0],"id_token":null}}]"#;
        assert_eq!(
            extract_refresh_token(data),
            Some("1//test-refresh-token".to_string())
        );
    }

    #[test]
    fn extract_refresh_token_missing_token() {
        let data = r#"[{"scopes":["scope"],"token":{"access_token":"ya29.test"}}]"#;
        assert_eq!(extract_refresh_token(data), None);
    }

    #[test]
    fn extract_refresh_token_empty_array() {
        assert_eq!(extract_refresh_token("[]"), None);
    }

    #[test]
    fn extract_refresh_token_invalid_json() {
        assert_eq!(extract_refresh_token("not json"), None);
    }

    #[test]
    fn extract_refresh_token_object_format() {
        // HashMap<String, TokenInfo> format from EncryptedTokenStorage
        let data = r#"{"key":{"access_token":"ya29","refresh_token":"1//tok"}}"#;
        assert_eq!(extract_refresh_token(data), Some("1//tok".to_string()));
    }

    // ── is_workspace_admin_scope tests ──────────────────────────────────

    #[test]
    fn is_workspace_admin_scope_apps_alerts() {
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/apps.alerts"
        ));
    }

    #[test]
    fn is_workspace_admin_scope_apps_groups_settings() {
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/apps.groups.settings"
        ));
    }

    #[test]
    fn is_workspace_admin_scope_apps_licensing() {
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/apps.licensing"
        ));
    }

    #[test]
    fn is_workspace_admin_scope_cloud_identity() {
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/cloud-identity.groups"
        ));
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/cloud-identity.devices"
        ));
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/cloud-identity.policies"
        ));
    }

    #[test]
    fn is_workspace_admin_scope_ediscovery() {
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/ediscovery"
        ));
    }

    #[test]
    fn is_workspace_admin_scope_directory_readonly() {
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/directory.readonly"
        ));
    }

    #[test]
    fn is_workspace_admin_scope_groups() {
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/groups"
        ));
    }

    #[test]
    fn is_workspace_admin_scope_normal_scopes_not_admin() {
        // Consumer/personal-account scopes must NOT be classified as admin-only
        assert!(!is_workspace_admin_scope(
            "https://www.googleapis.com/auth/drive"
        ));
        assert!(!is_workspace_admin_scope(
            "https://www.googleapis.com/auth/gmail.modify"
        ));
        assert!(!is_workspace_admin_scope(
            "https://www.googleapis.com/auth/calendar"
        ));
        assert!(!is_workspace_admin_scope(
            "https://www.googleapis.com/auth/spreadsheets"
        ));
        assert!(!is_workspace_admin_scope(
            "https://www.googleapis.com/auth/chat.messages"
        ));
    }

    // ── is_workspace_admin_scope – new patterns ─────────────────────────

    #[test]
    fn is_workspace_admin_scope_chat_admin() {
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/chat.admin.memberships"
        ));
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/chat.admin.memberships.readonly"
        ));
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/chat.admin.spaces"
        ));
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/chat.admin.spaces.readonly"
        ));
    }

    #[test]
    fn is_workspace_admin_scope_classroom() {
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/classroom.courses"
        ));
        assert!(is_workspace_admin_scope(
            "https://www.googleapis.com/auth/classroom.rosters"
        ));
    }

    // ── scope_matches_service tests ──────────────────────────────────────

    #[test]
    fn scope_matches_service_exact_match() {
        let services: HashSet<String> = ["drive"].iter().map(|s| s.to_string()).collect();
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/drive",
            &services
        ));
    }

    #[test]
    fn scope_matches_service_aliases() {
        let services: HashSet<String> = ["sheets", "docs", "slides"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/spreadsheets",
            &services
        ));
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/documents",
            &services
        ));
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/presentations",
            &services
        ));
    }

    #[test]
    fn scope_matches_service_prefix_match() {
        let services: HashSet<String> = ["drive"].iter().map(|s| s.to_string()).collect();
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/drive.readonly",
            &services
        ));
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/drive.metadata.readonly",
            &services
        ));
    }

    #[test]
    fn scope_matches_service_no_match() {
        let services: HashSet<String> = ["gmail"].iter().map(|s| s.to_string()).collect();
        assert!(!scope_matches_service(
            "https://www.googleapis.com/auth/drive",
            &services
        ));
    }

    #[test]
    fn scope_matches_service_cloud_platform_always_matches() {
        let services: HashSet<String> = ["drive"].iter().map(|s| s.to_string()).collect();
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/cloud-platform",
            &services
        ));
    }

    #[test]
    fn scope_matches_service_no_partial_name_collision() {
        // "drive" should NOT match "driveactivity" or similar
        let services: HashSet<String> = ["drive"].iter().map(|s| s.to_string()).collect();
        assert!(!scope_matches_service(
            "https://www.googleapis.com/auth/driveactivity",
            &services
        ));
    }

    #[test]
    fn scope_matches_service_people_contacts() {
        let services: HashSet<String> = ["people"].iter().map(|s| s.to_string()).collect();
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/contacts",
            &services
        ));
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/contacts.readonly",
            &services
        ));
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/contacts.other.readonly",
            &services
        ));
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/directory.readonly",
            &services
        ));
    }

    #[test]
    fn scope_matches_service_chat() {
        let services: HashSet<String> = ["chat"].iter().map(|s| s.to_string()).collect();
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/chat.spaces",
            &services
        ));
        assert!(scope_matches_service(
            "https://www.googleapis.com/auth/chat.messages",
            &services
        ));
    }

    // ── services filter integration tests ────────────────────────────────

    #[test]
    fn resolve_scopes_with_services_filter() {
        let scopes =
            run_resolve_scopes_with_services(ScopeMode::Default, None, &["drive", "gmail"]);
        assert!(!scopes.is_empty());
        for scope in &scopes {
            let short = scope
                .strip_prefix("https://www.googleapis.com/auth/")
                .unwrap_or(scope);
            assert!(
                short.starts_with("drive")
                    || short.starts_with("gmail")
                    || short == "cloud-platform",
                "Unexpected scope with service filter: {scope}"
            );
        }
    }

    #[test]
    fn resolve_scopes_services_filter_unknown_service_ignored() {
        let scopes =
            run_resolve_scopes_with_services(ScopeMode::Default, None, &["drive", "nonexistent"]);
        assert!(!scopes.is_empty());
        // Should contain drive scope but not be affected by nonexistent
        assert!(scopes.iter().any(|s| s.contains("/auth/drive")));
    }

    #[test]
    fn resolve_scopes_services_takes_priority_with_readonly() {
        let scopes = run_resolve_scopes_with_services(ScopeMode::Readonly, None, &["drive"]);
        assert!(!scopes.is_empty());
        for scope in &scopes {
            let short = scope
                .strip_prefix("https://www.googleapis.com/auth/")
                .unwrap_or(scope);
            assert!(
                short.starts_with("drive") || short == "cloud-platform",
                "Unexpected scope with service + readonly filter: {scope}"
            );
        }
    }

    #[test]
    fn resolve_scopes_services_takes_priority_with_full() {
        let scopes = run_resolve_scopes_with_services(ScopeMode::Full, None, &["gmail"]);
        assert!(!scopes.is_empty());
        for scope in &scopes {
            let short = scope
                .strip_prefix("https://www.googleapis.com/auth/")
                .unwrap_or(scope);
            assert!(
                short.starts_with("gmail") || short == "cloud-platform",
                "Unexpected scope with service + full filter: {scope}"
            );
        }
    }

    #[test]
    fn resolve_scopes_explicit_scopes_bypass_services_filter() {
        // Custom scopes take priority over services filter
        let scopes = run_resolve_scopes_with_services(
            ScopeMode::Custom(vec!["https://www.googleapis.com/auth/calendar".to_string()]),
            None,
            &["drive"],
        );
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0], "https://www.googleapis.com/auth/calendar");
    }

    #[test]
    fn filter_scopes_by_services_none_returns_all() {
        let scopes = vec![
            "https://www.googleapis.com/auth/drive".to_string(),
            "https://www.googleapis.com/auth/gmail.modify".to_string(),
        ];
        let result = filter_scopes_by_services(scopes.clone(), None);
        assert_eq!(result, scopes);
    }

    #[test]
    fn filter_scopes_by_services_empty_set_returns_all() {
        let scopes = vec![
            "https://www.googleapis.com/auth/drive".to_string(),
            "https://www.googleapis.com/auth/gmail.modify".to_string(),
        ];
        let empty: HashSet<String> = HashSet::new();
        let result = filter_scopes_by_services(scopes.clone(), Some(&empty));
        assert_eq!(result, scopes);
    }

    #[test]
    fn filter_restrictive_removes_metadata_when_broader_present() {
        let scopes = vec![
            "https://www.googleapis.com/auth/gmail.modify".to_string(),
            "https://www.googleapis.com/auth/gmail.metadata".to_string(),
            "https://www.googleapis.com/auth/drive".to_string(),
        ];
        let result = filter_redundant_restrictive_scopes(scopes);
        assert!(!result.iter().any(|s| s.contains("gmail.metadata")));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn filter_restrictive_removes_metadata_when_full_gmail_present() {
        let scopes = vec![
            "https://mail.google.com/".to_string(),
            "https://www.googleapis.com/auth/gmail.metadata".to_string(),
        ];
        let result = filter_redundant_restrictive_scopes(scopes);
        assert_eq!(result, vec!["https://mail.google.com/"]);
    }

    #[test]
    fn filter_restrictive_keeps_metadata_when_only_scope() {
        let scopes = vec![
            "https://www.googleapis.com/auth/gmail.metadata".to_string(),
            "https://www.googleapis.com/auth/drive".to_string(),
        ];
        let result = filter_redundant_restrictive_scopes(scopes.clone());
        assert_eq!(result, scopes);
    }

    #[test]
    fn mask_secret_long_string() {
        let masked = mask_secret("GOCSPX-abcdefghijklmnopqrstuvwxyz");
        assert_eq!(masked, "GOCS...wxyz");
    }

    #[test]
    fn mask_secret_short_string() {
        // 8 chars or fewer should be fully masked
        assert_eq!(mask_secret("12345678"), "***");
        assert_eq!(mask_secret("short"), "***");
        assert_eq!(mask_secret(""), "***");
    }

    #[test]
    fn mask_secret_boundary() {
        // Exactly 9 chars — first 4 + last 4 with "..." in between
        assert_eq!(mask_secret("123456789"), "1234...6789");
    }

    #[test]
    fn mask_secret_multibyte_utf8() {
        // Multi-byte chars must not panic (previously used byte slicing)
        assert_eq!(mask_secret("áéíóúñüÁÉÍÓÚ"), "áéíó...ÉÍÓÚ");
        // Short multi-byte — should fully mask
        assert_eq!(mask_secret("café"), "***");
        // Exactly at boundary with multi-byte (9 Greek chars)
        assert_eq!(mask_secret("αβγδεζηθι"), "αβγδ...ζηθι");
    }

    #[test]
    fn find_unmatched_services_identifies_missing() {
        let scopes = vec![
            "https://www.googleapis.com/auth/drive".to_string(),
            "https://www.googleapis.com/auth/cloud-platform".to_string(),
        ];
        let services: HashSet<String> = ["drive", "chat"].iter().map(|s| s.to_string()).collect();
        let missing = find_unmatched_services(&scopes, &services);
        assert!(!missing.contains("drive"));
        assert!(missing.contains("chat"));
    }

    #[test]
    fn find_unmatched_services_all_matched() {
        let scopes = vec![
            "https://www.googleapis.com/auth/drive".to_string(),
            "https://www.googleapis.com/auth/gmail.modify".to_string(),
        ];
        let services: HashSet<String> = ["drive", "gmail"].iter().map(|s| s.to_string()).collect();
        let missing = find_unmatched_services(&scopes, &services);
        assert!(missing.is_empty());
    }

    fn make_test_discovery_doc(scope_urls: &[&str]) -> crate::discovery::RestDescription {
        let mut scopes = std::collections::HashMap::new();
        for url in scope_urls {
            scopes.insert(
                url.to_string(),
                crate::discovery::ScopeDescription {
                    description: Some("test".to_string()),
                },
            );
        }
        crate::discovery::RestDescription {
            auth: Some(crate::discovery::AuthDescription {
                oauth2: Some(crate::discovery::OAuth2Description {
                    scopes: Some(scopes),
                }),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn extract_scopes_from_doc_filters_app_only() {
        let doc = make_test_discovery_doc(&[
            "https://www.googleapis.com/auth/chat.messages",
            "https://www.googleapis.com/auth/chat.bot",
            "https://www.googleapis.com/auth/chat.app.spaces",
            "https://www.googleapis.com/auth/chat.spaces",
        ]);
        let mut result = extract_scopes_from_doc(&doc, false);
        result.sort();
        assert_eq!(
            result,
            vec![
                "https://www.googleapis.com/auth/chat.messages",
                "https://www.googleapis.com/auth/chat.spaces",
            ]
        );
    }

    #[test]
    fn extract_scopes_from_doc_readonly_filter() {
        let doc = make_test_discovery_doc(&[
            "https://www.googleapis.com/auth/chat.messages",
            "https://www.googleapis.com/auth/chat.messages.readonly",
            "https://www.googleapis.com/auth/chat.spaces",
            "https://www.googleapis.com/auth/chat.spaces.readonly",
        ]);
        let mut result = extract_scopes_from_doc(&doc, true);
        result.sort();
        assert_eq!(
            result,
            vec![
                "https://www.googleapis.com/auth/chat.messages.readonly",
                "https://www.googleapis.com/auth/chat.spaces.readonly",
            ]
        );
    }

    #[test]
    fn extract_scopes_from_doc_empty_auth() {
        let doc = crate::discovery::RestDescription {
            auth: None,
            ..Default::default()
        };
        let result = extract_scopes_from_doc(&doc, false);
        assert!(result.is_empty());
    }

    #[test]
    fn build_proxy_auth_url_encodes_scope_and_redirect_uri() {
        let scopes = vec![
            "https://www.googleapis.com/auth/drive".to_string(),
            "openid".to_string(),
        ];
        let url = build_proxy_auth_url(
            "client id",
            "http://localhost:8080/callback path",
            &scopes,
            &AuthUrlExtras::default(),
        );

        assert!(url.contains("client_id=client%20id"));
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback%20path"));
        assert!(url.contains(&format!(
            "scope={}",
            urlencoding("https://www.googleapis.com/auth/drive openid")
        )));
    }

    #[test]
    fn extract_authorization_code_returns_code() {
        let code =
            extract_authorization_code("GET /?state=abc&code=4/test-code&scope=openid HTTP/1.1")
                .unwrap();
        assert_eq!(code, "4/test-code");
    }

    #[test]
    fn extract_authorization_code_rejects_missing_code() {
        let err = extract_authorization_code("GET /?state=abc HTTP/1.1").unwrap_err();
        assert!(err.to_string().contains("No authorization code"));
    }

    #[test]
    fn read_refresh_token_from_cache_reads_encrypted_storage() {
        let token_data = r#"[{"token":{"refresh_token":"1//refresh-token"}}]"#;
        let encrypted = crate::credential_store::encrypt(token_data.as_bytes()).unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, &encrypted).unwrap();

        let refresh_token = read_refresh_token_from_cache(file.path()).unwrap();
        assert_eq!(refresh_token, "1//refresh-token");
    }

    #[test]
    fn read_refresh_token_from_cache_requires_refresh_token() {
        let token_data = r#"[{"token":{"access_token":"ya29.no-refresh"}}]"#;
        let encrypted = crate::credential_store::encrypt(token_data.as_bytes()).unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, &encrypted).unwrap();

        let err = read_refresh_token_from_cache(file.path()).unwrap_err();
        assert!(err.to_string().contains("no refresh token was returned"));
    }

    // -- multi-account -------------------------------------------------------

    use crate::accounts::Registry;

    struct ConfigDirGuard(Option<std::ffi::OsString>);

    impl ConfigDirGuard {
        fn set(path: &Path) -> Self {
            let previous = std::env::var_os("GOOGLE_WORKSPACE_CLI_CONFIG_DIR");
            std::env::set_var("GOOGLE_WORKSPACE_CLI_CONFIG_DIR", path);
            Self(previous)
        }
    }

    impl Drop for ConfigDirGuard {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("GOOGLE_WORKSPACE_CLI_CONFIG_DIR", v),
                None => std::env::remove_var("GOOGLE_WORKSPACE_CLI_CONFIG_DIR"),
            }
        }
    }

    fn account_reason(err: GwsError) -> String {
        match err {
            GwsError::Account { reason, .. } => reason,
            other => panic!("expected account error, got {other:?}"),
        }
    }

    #[test]
    fn auth_url_extras_appends_params() {
        let extras = AuthUrlExtras {
            login_hint: Some("me+x@example.com".to_string()),
            include_granted_scopes: true,
        };
        assert_eq!(
            extras.apply("https://a/b?x=1"),
            "https://a/b?x=1&login_hint=me%2Bx%40example%2Ecom&include_granted_scopes=true"
        );
        assert_eq!(AuthUrlExtras::default().apply("https://a/b"), "https://a/b");
        let incremental = AuthUrlExtras {
            login_hint: None,
            include_granted_scopes: true,
        };
        assert_eq!(
            incremental.apply("https://a/b"),
            "https://a/b?include_granted_scopes=true"
        );
    }

    #[test]
    fn proxy_auth_url_includes_extras() {
        let url = build_proxy_auth_url(
            "id",
            "http://localhost:1",
            &["s".to_string()],
            &AuthUrlExtras {
                login_hint: Some("a@b.co".to_string()),
                include_granted_scopes: true,
            },
        );
        assert!(url.contains("&login_hint=a%40b%2Eco"));
        assert!(url.ends_with("&include_granted_scopes=true"));
    }

    #[test]
    fn login_target_fresh_dir_starts_registry() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            LoginTarget::decide(dir.path(), None).unwrap(),
            LoginTarget::Account {
                requested: None,
                registry: Registry::default()
            }
        );
        assert_eq!(
            LoginTarget::decide(dir.path(), Some("Me@X.com")).unwrap(),
            LoginTarget::Account {
                requested: Some("me@x.com".to_string()),
                registry: Registry::default()
            }
        );
    }

    #[test]
    fn login_target_legacy_dir_keeps_single_account() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("credentials.enc"), b"x").unwrap();
        assert_eq!(
            LoginTarget::decide(dir.path(), None).unwrap(),
            LoginTarget::Legacy
        );
        assert_eq!(
            account_reason(LoginTarget::decide(dir.path(), Some("a@x.com")).unwrap_err()),
            "noAccountRegistry"
        );
    }

    #[test]
    fn login_target_registry_wins_over_legacy_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("credentials.enc"), b"x").unwrap();
        let mut registry = Registry::default();
        registry.upsert("a@x.com", vec![], "t");
        registry.save(dir.path()).unwrap();
        assert_eq!(
            LoginTarget::decide(dir.path(), None).unwrap(),
            LoginTarget::Account {
                requested: None,
                registry
            }
        );
    }

    #[test]
    fn login_target_rejects_invalid_account() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            LoginTarget::decide(dir.path(), Some("../../etc")).unwrap_err(),
            GwsError::Validation(_)
        ));
    }

    #[test]
    fn check_login_email_rejects_mismatch() {
        let registry = Registry::default();
        assert!(check_login_email(None, "a@x.com", &registry).is_ok());
        assert!(check_login_email(Some("a@x.com"), "a@x.com", &registry).is_ok());
        assert_eq!(
            account_reason(check_login_email(Some("a@x.com"), "b@x.com", &registry).unwrap_err()),
            "accountMismatch"
        );
    }

    #[test]
    fn clear_account_caches_keeps_credentials() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["token_cache.json", "account_timezone", "credentials.enc"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        clear_account_caches(dir.path());
        assert!(!dir.path().join("token_cache.json").exists());
        assert!(!dir.path().join("account_timezone").exists());
        assert!(dir.path().join("credentials.enc").exists());
    }

    fn write_file_key_source(dir: &Path, key: &[u8; 32], creds: &str) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let key_path = dir.join(".encryption_key");
        std::fs::write(&key_path, STANDARD.encode(key)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let data = credential_store::encrypt_with_key(key, creds.as_bytes()).unwrap();
        std::fs::write(dir.join("credentials.enc"), data).unwrap();
    }

    const USER_CREDS: &str = r#"{"type":"authorized_user","client_id":"cid","client_secret":"csec","refresh_token":"rt"}"#;

    #[test]
    fn read_import_source_decrypts_with_file_key() {
        let dir = tempfile::tempdir().unwrap();
        write_file_key_source(dir.path(), &[7u8; 32], USER_CREDS);
        let src = read_import_source(dir.path(), true).unwrap();
        assert_eq!(src.client_id, "cid");
        assert_eq!(src.client_secret, "csec");
        assert_eq!(src.refresh_token, "rt");
        assert_eq!(src.creds_json, USER_CREDS);
    }

    #[test]
    fn read_import_source_wrong_key_errors_and_keeps_file() {
        let dir = tempfile::tempdir().unwrap();
        write_file_key_source(dir.path(), &[7u8; 32], USER_CREDS);
        let enc = std::fs::read(dir.path().join("credentials.enc")).unwrap();
        // Replace the key file with a different key.
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        std::fs::write(
            dir.path().join(".encryption_key"),
            STANDARD.encode([9u8; 32]),
        )
        .unwrap();
        match read_import_source(dir.path(), true).unwrap_err() {
            GwsError::Auth(msg) => assert!(msg.contains("Could not decrypt"), "got: {msg}"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            std::fs::read(dir.path().join("credentials.enc")).unwrap(),
            enc
        );
    }

    #[test]
    fn read_import_source_requires_key_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("credentials.enc"), b"0123456789abcdef").unwrap();
        assert!(matches!(
            read_import_source(dir.path(), true).unwrap_err(),
            GwsError::Validation(_)
        ));
    }

    #[test]
    fn read_import_source_rejects_service_accounts() {
        let dir = tempfile::tempdir().unwrap();
        write_file_key_source(
            dir.path(),
            &[7u8; 32],
            r#"{"type":"service_account","client_email":"sa@p.iam.gserviceaccount.com"}"#,
        );
        assert!(matches!(
            read_import_source(dir.path(), true).unwrap_err(),
            GwsError::Validation(_)
        ));
    }

    #[test]
    #[serial_test::serial]
    fn default_command_updates_registry() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = ConfigDirGuard::set(dir.path());
        let mut registry = Registry::default();
        registry.upsert("a@x.com", vec![], "t");
        registry.upsert("b@x.com", vec![], "t");
        registry.save(dir.path()).unwrap();

        handle_default("B@X.com").unwrap();
        let loaded = Registry::load(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.default.as_deref(), Some("b@x.com"));

        assert_eq!(
            account_reason(handle_default("c@x.com").unwrap_err()),
            "unknownAccount"
        );
        assert!(handle_list().is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn default_command_without_registry_errors() {
        let dir = tempfile::tempdir().unwrap();
        let _guard = ConfigDirGuard::set(dir.path());
        assert!(handle_default("a@x.com").is_err());
        assert!(handle_list().is_ok());
    }

    #[test]
    fn client_id_of_reads_installed_client() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client_secret.json");
        std::fs::write(
            &path,
            r#"{"installed":{"client_id":"abc","client_secret":"s","project_id":"p","auth_uri":"u","token_uri":"t"}}"#,
        )
        .unwrap();
        assert_eq!(client_id_of(&path).as_deref(), Some("abc"));
        assert_eq!(client_id_of(&dir.path().join("missing.json")), None);
    }
}
