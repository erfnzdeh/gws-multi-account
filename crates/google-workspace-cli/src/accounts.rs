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

//! Multiple accounts.
//!
//! When `accounts.toml` exists in the config directory, credentials live in
//! per-account directories (`accounts/<email>/`) and every invocation runs as
//! exactly one account, chosen by `--account`, `GOOGLE_WORKSPACE_CLI_ACCOUNT`,
//! or the registry default. Commands that write data must name the account
//! explicitly once more than one account is configured.
//!
//! Without a registry the CLI behaves as a single-account install, exactly
//! like before, so existing config directories keep working unchanged.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::error::GwsError;
use crate::output::sanitize_for_terminal;

/// Registry file name inside the config directory.
pub const REGISTRY_FILE: &str = "accounts.toml";
/// Directory (inside the config directory) holding one directory per account.
pub const ACCOUNTS_DIR: &str = "accounts";
/// Environment variable selecting the account, overridden by `--account`.
pub const ACCOUNT_ENV: &str = "GOOGLE_WORKSPACE_CLI_ACCOUNT";

const ACCOUNT_FLAG: &str = "--account";

/// Environment variables that supply credentials not tied to any account.
const RAW_CREDENTIAL_ENVS: &[&str] = &[
    "GOOGLE_WORKSPACE_CLI_TOKEN",
    "GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE",
];

/// Helpers that only read data. Any helper not listed here is treated as a
/// write, so a new helper fails closed until it is classified.
const READ_HELPERS: &[&str] = &[
    "+agenda",
    "+meeting-prep",
    "+read",
    "+sanitize-prompt",
    "+sanitize-response",
    "+standup-report",
    "+triage",
    "+weekly-digest",
];

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// On-disk representation of `accounts.toml`.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(default)]
    pub accounts: BTreeMap<String, AccountMeta>,
}

/// Metadata recorded for each account.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountMeta {
    /// RFC 3339 timestamp of when the account was first added.
    pub added: String,
    /// Scopes granted at the last login, used to merge scopes on re-login.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

impl Registry {
    pub fn path(config_dir: &Path) -> PathBuf {
        config_dir.join(REGISTRY_FILE)
    }

    /// Loads the registry, or `None` if the config directory has none.
    pub fn load(config_dir: &Path) -> Result<Option<Self>, GwsError> {
        let path = Self::path(config_dir);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(GwsError::Validation(format!(
                    "Failed to read {}: {e}",
                    path.display()
                )))
            }
        };
        let registry: Registry = toml::from_str(&text).map_err(|e| {
            GwsError::Validation(format!(
                "Failed to parse {}: {}",
                path.display(),
                sanitize_for_terminal(&e.to_string())
            ))
        })?;
        Ok(Some(registry))
    }

    /// Writes the registry atomically with 0600 permissions.
    pub fn save(&self, config_dir: &Path) -> Result<(), GwsError> {
        create_private_dir(config_dir)?;
        let text = toml::to_string_pretty(self)
            .map_err(|e| GwsError::Other(anyhow::anyhow!("Failed to serialize accounts: {e}")))?;
        let path = Self::path(config_dir);
        crate::fs_util::atomic_write(&path, text.as_bytes())
            .map_err(|e| GwsError::Validation(format!("Failed to write {}: {e}", path.display())))
    }

    /// Configured account emails, sorted.
    pub fn emails(&self) -> Vec<String> {
        self.accounts.keys().cloned().collect()
    }

    /// Adds an account or updates its scopes. The first account added to an
    /// empty registry becomes the default.
    pub fn upsert(&mut self, email: &str, scopes: Vec<String>, now: &str) {
        if self.accounts.is_empty() && self.default.is_none() {
            self.default = Some(email.to_string());
        }
        let meta = self
            .accounts
            .entry(email.to_string())
            .or_insert_with(|| AccountMeta {
                added: now.to_string(),
                scopes: Vec::new(),
            });
        meta.scopes = scopes;
    }

    /// Removes an account. Removing the default leaves no default: another
    /// account is never promoted silently. Returns whether it existed.
    pub fn remove(&mut self, email: &str) -> bool {
        if self.default.as_deref() == Some(email) {
            self.default = None;
        }
        self.accounts.remove(email).is_some()
    }

    pub fn set_default(&mut self, email: &str) -> Result<(), GwsError> {
        if !self.accounts.contains_key(email) {
            return Err(account_error(
                "unknownAccount",
                format!("Account '{email}' is not configured."),
                Some(self),
            ));
        }
        self.default = Some(email.to_string());
        Ok(())
    }
}

/// Returns `existing` followed by any scopes from `new` not already present.
pub fn merge_scopes(existing: &[String], new: &[String]) -> Vec<String> {
    let mut merged = existing.to_vec();
    for scope in new {
        if !merged.contains(scope) {
            merged.push(scope.clone());
        }
    }
    merged
}

/// Directory holding one account's credentials and caches.
///
/// `email` must already be normalized with [`normalize_email`], which
/// guarantees it is a single safe path component.
pub fn account_dir(config_dir: &Path, email: &str) -> PathBuf {
    config_dir.join(ACCOUNTS_DIR).join(email)
}

/// Creates a directory (and parents) restricted to the current user.
pub fn create_private_dir(dir: &Path) -> Result<(), GwsError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| GwsError::Validation(format!("Failed to create {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            eprintln!(
                "Warning: failed to set permissions on {}: {e}",
                dir.display()
            );
        }
    }
    Ok(())
}

/// Validates an account email and returns its canonical (lowercase) form.
///
/// The value usually comes from `--account`, which agents may fill with
/// arbitrary text, and it becomes a directory name. Only plain ASCII email
/// addresses are accepted, so it can never contain path separators or be
/// `.`/`..`.
pub fn normalize_email(raw: &str) -> Result<String, GwsError> {
    let email = raw.trim().to_ascii_lowercase();
    let invalid = || {
        GwsError::Validation(format!(
            "Invalid account '{}': expected an email address such as me@example.com",
            sanitize_for_terminal(raw)
        ))
    };
    let (local, domain) = email.split_once('@').ok_or_else(invalid)?;
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c));
    let domain_ok = !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && !domain.contains("..")
        && !domain.starts_with(['.', '-'])
        && !domain.ends_with(['.', '-'])
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if local_ok && domain_ok {
        Ok(email)
    } else {
        Err(invalid())
    }
}

// ---------------------------------------------------------------------------
// Read/write classification
// ---------------------------------------------------------------------------

/// Whether a command only reads data or may change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// Classifies a Discovery method.
///
/// GET is a read. Any other verb is a read only if the method accepts a
/// `.readonly` scope: a read-only token cannot authorize a mutation, so this
/// catches read-only POSTs such as `calendar.freebusy.query`.
pub fn classify_method(http_method: &str, scopes: &[String]) -> Access {
    let is_get =
        http_method.eq_ignore_ascii_case("GET") || http_method.eq_ignore_ascii_case("HEAD");
    if is_get || scopes.iter().any(|s| s.ends_with(".readonly")) {
        Access::Read
    } else {
        Access::Write
    }
}

/// Classifies a `+helper` command by name. Unknown helpers are writes.
pub fn classify_helper(name: &str) -> Access {
    if READ_HELPERS.contains(&name) {
        Access::Read
    } else {
        Access::Write
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Where the selected account came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Flag,
    Env,
    Default,
}

/// The account an invocation runs as.
#[derive(Debug, Clone, PartialEq)]
pub struct Selection {
    pub email: String,
    pub dir: PathBuf,
    pub source: Source,
}

/// Which credentials an invocation uses.
#[derive(Debug, Clone, PartialEq)]
pub enum Active {
    /// No registry (or raw credentials from the environment): use the config
    /// directory's top-level files, as a single-account install does.
    Legacy,
    /// A registered account.
    Account(Selection),
}

/// Inputs to [`resolve`], gathered from flags and the environment.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    /// Value of `--account`, if given.
    pub flag: Option<&'a str>,
    /// Value of `GOOGLE_WORKSPACE_CLI_ACCOUNT`, if set.
    pub env: Option<&'a str>,
    /// Name of a set raw-credential environment variable, if any.
    pub raw_credential_env: Option<&'a str>,
    pub access: Access,
    /// Dry runs send nothing, so they never require an explicit account.
    pub dry_run: bool,
}

fn account_error(reason: &str, message: String, registry: Option<&Registry>) -> GwsError {
    GwsError::Account {
        reason: reason.to_string(),
        message,
        accounts: registry.map(Registry::emails).unwrap_or_default(),
        default: registry.and_then(|r| r.default.clone()),
    }
}

/// Decides which credentials an invocation uses. Pure, so every rule is unit
/// tested without touching the filesystem or environment.
pub fn resolve(
    req: &Request,
    registry: Option<&Registry>,
    config_dir: &Path,
) -> Result<Active, GwsError> {
    let requested = req.flag.or(req.env.filter(|v| !v.trim().is_empty()));

    if let Some(var) = req.raw_credential_env {
        if requested.is_some() {
            return Err(account_error(
                "accountConflict",
                format!(
                    "An account was selected (--account or {ACCOUNT_ENV}) but {var} is also set. \
                     Unset one of them."
                ),
                registry,
            ));
        }
        return Ok(Active::Legacy);
    }

    let Some(registry) = registry else {
        if let Some(raw) = requested {
            return Err(account_error(
                "noAccountRegistry",
                format!(
                    "Account '{}' was requested, but {} has no account registry. \
                     Run `gws auth login` or `gws auth import --from <dir>` to add accounts.",
                    sanitize_for_terminal(raw),
                    config_dir.display()
                ),
                None,
            ));
        }
        return Ok(Active::Legacy);
    };

    if let Some(raw) = requested {
        let email = normalize_email(raw)?;
        if !registry.accounts.contains_key(&email) {
            return Err(account_error(
                "unknownAccount",
                format!(
                    "Account '{email}' is not configured. Run `gws auth list` to see accounts."
                ),
                Some(registry),
            ));
        }
        let source = if req.flag.is_some() {
            Source::Flag
        } else {
            Source::Env
        };
        return Ok(Active::Account(Selection {
            dir: account_dir(config_dir, &email),
            email,
            source,
        }));
    }

    let count = registry.accounts.len();
    if count == 0 {
        return Err(account_error(
            "noAccounts",
            "No accounts are configured. Run `gws auth login` to add one.".to_string(),
            Some(registry),
        ));
    }

    if count > 1 && req.access == Access::Write && !req.dry_run {
        return Err(account_error(
            "accountRequired",
            format!(
                "This command writes data and {count} accounts are configured. \
                 Pass --account EMAIL (or set {ACCOUNT_ENV})."
            ),
            Some(registry),
        ));
    }

    let email = match &registry.default {
        Some(default) if registry.accounts.contains_key(default) => default.clone(),
        _ if count == 1 => registry.emails().remove(0),
        _ => {
            return Err(account_error(
                "accountRequired",
                format!(
                    "No default account is set and {count} accounts are configured. \
                     Pass --account EMAIL or run `gws auth default EMAIL`."
                ),
                Some(registry),
            ))
        }
    };
    Ok(Active::Account(Selection {
        dir: account_dir(config_dir, &email),
        email,
        source: Source::Default,
    }))
}

// ---------------------------------------------------------------------------
// Process-wide state
// ---------------------------------------------------------------------------

static CLI_FLAG: OnceLock<Option<String>> = OnceLock::new();
static ACTIVE: OnceLock<Active> = OnceLock::new();

/// Removes `--account EMAIL` / `--account=EMAIL` from `args`, wherever it
/// appears, and returns the remaining args and the value.
pub fn split_account_flag(args: Vec<String>) -> Result<(Vec<String>, Option<String>), GwsError> {
    let prefix = format!("{ACCOUNT_FLAG}=");
    let mut rest = Vec::with_capacity(args.len());
    let mut value: Option<String> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let found = if arg == ACCOUNT_FLAG {
            Some(iter.next().ok_or_else(|| {
                GwsError::Validation(format!("{ACCOUNT_FLAG} requires an email address"))
            })?)
        } else {
            arg.strip_prefix(&prefix).map(str::to_string)
        };
        match found {
            Some(v) => {
                if value
                    .as_ref()
                    .is_some_and(|prev| !prev.eq_ignore_ascii_case(&v))
                {
                    return Err(GwsError::Validation(format!(
                        "{ACCOUNT_FLAG} was given more than once with different values"
                    )));
                }
                value = Some(v);
            }
            None => rest.push(arg),
        }
    }
    Ok((rest, value))
}

/// Strips `--account` from the process args and remembers its value.
pub fn take_account_flag(args: Vec<String>) -> Result<Vec<String>, GwsError> {
    let (rest, value) = split_account_flag(args)?;
    let _ = CLI_FLAG.set(value);
    Ok(rest)
}

/// The `--account` value given on the command line, if any.
pub fn cli_flag() -> Option<&'static str> {
    CLI_FLAG.get().and_then(|v| v.as_deref())
}

/// The account requested by flag or environment, without consulting the
/// registry default.
pub fn requested_account() -> Option<String> {
    cli_flag().map(str::to_string).or_else(|| {
        std::env::var(ACCOUNT_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
    })
}

/// Resolves the account for this invocation once and remembers it.
///
/// Later calls return the first result regardless of `access`.
pub fn select(access: Access, dry_run: bool) -> Result<&'static Active, GwsError> {
    if let Some(active) = ACTIVE.get() {
        return Ok(active);
    }
    let config_dir = crate::auth_commands::config_dir();
    let registry = Registry::load(&config_dir)?;
    let env = std::env::var(ACCOUNT_ENV).ok();
    let raw_credential_env = RAW_CREDENTIAL_ENVS
        .iter()
        .find(|var| std::env::var(var).is_ok_and(|v| !v.is_empty()))
        .copied();
    let request = Request {
        flag: cli_flag(),
        env: env.as_deref(),
        raw_credential_env,
        access,
        dry_run,
    };
    let active = resolve(&request, registry.as_ref(), &config_dir)?;
    if let Active::Account(selection) = &active {
        let several = registry.as_ref().is_some_and(|r| r.accounts.len() > 1);
        if selection.source == Source::Default && several {
            eprintln!("gws: using default account {}", selection.email);
        }
    }
    Ok(ACTIVE.get_or_init(|| active))
}

/// Pins this invocation to a specific account directory (used by `auth login`
/// and `auth import`, which create accounts rather than select them).
pub fn set_active(active: Active) {
    let _ = ACTIVE.set(active);
}

/// The selected account, if this invocation runs as a registered account.
pub fn active_account() -> Option<&'static Selection> {
    match ACTIVE.get() {
        Some(Active::Account(selection)) => Some(selection),
        _ => None,
    }
}

/// Directory holding the credentials and caches this invocation uses: the
/// selected account's directory, or the config directory itself.
pub fn credential_dir() -> PathBuf {
    match active_account() {
        Some(selection) => selection.dir.clone(),
        None => crate::auth_commands::config_dir(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(emails: &[&str], default: Option<&str>) -> Registry {
        let mut r = Registry::default();
        for e in emails {
            r.accounts.insert(e.to_string(), AccountMeta::default());
        }
        r.default = default.map(str::to_string);
        r
    }

    fn req(access: Access) -> Request<'static> {
        Request {
            flag: None,
            env: None,
            raw_credential_env: None,
            access,
            dry_run: false,
        }
    }

    fn reason(err: GwsError) -> String {
        match err {
            GwsError::Account { reason, .. } => reason,
            other => panic!("expected account error, got {other:?}"),
        }
    }

    fn selected(active: Active) -> (String, Source) {
        match active {
            Active::Account(s) => (s.email, s.source),
            Active::Legacy => panic!("expected an account"),
        }
    }

    const DIR: &str = "/cfg";

    // -- normalize_email ----------------------------------------------------

    #[test]
    fn normalize_lowercases_and_trims() {
        assert_eq!(
            normalize_email("  Me@Example.COM ").unwrap(),
            "me@example.com"
        );
        assert_eq!(
            normalize_email("first.last+tag@sub.example.org").unwrap(),
            "first.last+tag@sub.example.org"
        );
    }

    #[test]
    fn normalize_rejects_unsafe_values() {
        for bad in [
            "",
            "me",
            "@example.com",
            "me@",
            "me@localhost",
            "../../.ssh",
            "me@ex/ample.com",
            "me/x@example.com",
            "me@example..com",
            "me@.example.com",
            "me@example.com.",
            "a@b@example.com",
            "me@exa mple.com",
            "me\u{7}@example.com",
            "mé@example.com",
        ] {
            assert!(normalize_email(bad).is_err(), "should reject {bad:?}");
        }
    }

    // -- classification -----------------------------------------------------

    #[test]
    fn classify_get_is_read() {
        assert_eq!(classify_method("GET", &[]), Access::Read);
        assert_eq!(classify_method("get", &[]), Access::Read);
    }

    #[test]
    fn classify_post_with_readonly_scope_is_read() {
        let scopes = vec![
            "https://www.googleapis.com/auth/calendar".to_string(),
            "https://www.googleapis.com/auth/calendar.readonly".to_string(),
        ];
        assert_eq!(classify_method("POST", &scopes), Access::Read);
    }

    #[test]
    fn classify_mutations_are_writes() {
        let scopes = vec!["https://www.googleapis.com/auth/gmail.modify".to_string()];
        assert_eq!(classify_method("POST", &scopes), Access::Write);
        assert_eq!(classify_method("DELETE", &[]), Access::Write);
        assert_eq!(classify_method("PATCH", &[]), Access::Write);
    }

    #[test]
    fn classify_helpers() {
        assert_eq!(classify_helper("+triage"), Access::Read);
        assert_eq!(classify_helper("+agenda"), Access::Read);
        assert_eq!(classify_helper("+send"), Access::Write);
        assert_eq!(classify_helper("+brand-new-helper"), Access::Write);
    }

    // -- resolve ------------------------------------------------------------

    #[test]
    fn no_registry_is_legacy() {
        let active = resolve(&req(Access::Write), None, Path::new(DIR)).unwrap();
        assert_eq!(active, Active::Legacy);
    }

    #[test]
    fn no_registry_with_requested_account_errors() {
        let mut r = req(Access::Read);
        r.flag = Some("a@x.com");
        assert_eq!(
            reason(resolve(&r, None, Path::new(DIR)).unwrap_err()),
            "noAccountRegistry"
        );
        let mut r = req(Access::Read);
        r.env = Some("a@x.com");
        assert_eq!(
            reason(resolve(&r, None, Path::new(DIR)).unwrap_err()),
            "noAccountRegistry"
        );
    }

    #[test]
    fn raw_credentials_conflict_with_selection() {
        let reg = registry(&["a@x.com"], Some("a@x.com"));
        let mut r = req(Access::Read);
        r.raw_credential_env = Some("GOOGLE_WORKSPACE_CLI_TOKEN");
        assert_eq!(
            resolve(&r, Some(&reg), Path::new(DIR)).unwrap(),
            Active::Legacy
        );
        r.flag = Some("a@x.com");
        assert_eq!(
            reason(resolve(&r, Some(&reg), Path::new(DIR)).unwrap_err()),
            "accountConflict"
        );
    }

    #[test]
    fn flag_beats_env() {
        let reg = registry(&["a@x.com", "b@x.com"], Some("a@x.com"));
        let mut r = req(Access::Write);
        r.flag = Some("B@X.com");
        r.env = Some("a@x.com");
        let (email, source) = selected(resolve(&r, Some(&reg), Path::new(DIR)).unwrap());
        assert_eq!((email.as_str(), source), ("b@x.com", Source::Flag));
    }

    #[test]
    fn env_counts_as_explicit_for_writes() {
        let reg = registry(&["a@x.com", "b@x.com"], Some("a@x.com"));
        let mut r = req(Access::Write);
        r.env = Some("b@x.com");
        let (email, source) = selected(resolve(&r, Some(&reg), Path::new(DIR)).unwrap());
        assert_eq!((email.as_str(), source), ("b@x.com", Source::Env));
    }

    #[test]
    fn empty_env_is_ignored() {
        let reg = registry(&["a@x.com"], Some("a@x.com"));
        let mut r = req(Access::Read);
        r.env = Some("  ");
        let (_, source) = selected(resolve(&r, Some(&reg), Path::new(DIR)).unwrap());
        assert_eq!(source, Source::Default);
    }

    #[test]
    fn unknown_account_errors_with_list() {
        let reg = registry(&["a@x.com", "b@x.com"], Some("a@x.com"));
        let mut r = req(Access::Read);
        r.flag = Some("c@x.com");
        match resolve(&r, Some(&reg), Path::new(DIR)).unwrap_err() {
            GwsError::Account {
                reason,
                accounts,
                default,
                ..
            } => {
                assert_eq!(reason, "unknownAccount");
                assert_eq!(accounts, vec!["a@x.com", "b@x.com"]);
                assert_eq!(default.as_deref(), Some("a@x.com"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn invalid_flag_is_validation_error() {
        let reg = registry(&["a@x.com"], Some("a@x.com"));
        let mut r = req(Access::Read);
        r.flag = Some("../../etc");
        assert!(matches!(
            resolve(&r, Some(&reg), Path::new(DIR)).unwrap_err(),
            GwsError::Validation(_)
        ));
    }

    #[test]
    fn reads_use_default() {
        let reg = registry(&["a@x.com", "b@x.com"], Some("b@x.com"));
        let active = resolve(&req(Access::Read), Some(&reg), Path::new(DIR)).unwrap();
        match active {
            Active::Account(s) => {
                assert_eq!(s.email, "b@x.com");
                assert_eq!(s.source, Source::Default);
                assert_eq!(s.dir, Path::new("/cfg/accounts/b@x.com"));
            }
            Active::Legacy => panic!("expected account"),
        }
    }

    #[test]
    fn writes_require_explicit_account_with_several_accounts() {
        let reg = registry(&["a@x.com", "b@x.com"], Some("a@x.com"));
        assert_eq!(
            reason(resolve(&req(Access::Write), Some(&reg), Path::new(DIR)).unwrap_err()),
            "accountRequired"
        );
    }

    #[test]
    fn dry_run_writes_use_default() {
        let reg = registry(&["a@x.com", "b@x.com"], Some("a@x.com"));
        let mut r = req(Access::Write);
        r.dry_run = true;
        let (email, _) = selected(resolve(&r, Some(&reg), Path::new(DIR)).unwrap());
        assert_eq!(email, "a@x.com");
    }

    #[test]
    fn single_account_allows_default_writes() {
        let reg = registry(&["a@x.com"], Some("a@x.com"));
        let (email, _) =
            selected(resolve(&req(Access::Write), Some(&reg), Path::new(DIR)).unwrap());
        assert_eq!(email, "a@x.com");
    }

    #[test]
    fn single_account_without_default_is_used() {
        let reg = registry(&["a@x.com"], None);
        let (email, _) =
            selected(resolve(&req(Access::Write), Some(&reg), Path::new(DIR)).unwrap());
        assert_eq!(email, "a@x.com");
    }

    #[test]
    fn several_accounts_without_default_require_account_for_reads() {
        let reg = registry(&["a@x.com", "b@x.com"], None);
        assert_eq!(
            reason(resolve(&req(Access::Read), Some(&reg), Path::new(DIR)).unwrap_err()),
            "accountRequired"
        );
    }

    #[test]
    fn stale_default_is_not_used() {
        let reg = registry(&["a@x.com", "b@x.com"], Some("gone@x.com"));
        assert_eq!(
            reason(resolve(&req(Access::Read), Some(&reg), Path::new(DIR)).unwrap_err()),
            "accountRequired"
        );
    }

    #[test]
    fn empty_registry_errors() {
        let reg = registry(&[], None);
        assert_eq!(
            reason(resolve(&req(Access::Read), Some(&reg), Path::new(DIR)).unwrap_err()),
            "noAccounts"
        );
    }

    // -- registry -----------------------------------------------------------

    #[test]
    fn first_account_becomes_default() {
        let mut reg = Registry::default();
        reg.upsert("a@x.com", vec![], "t1");
        reg.upsert("b@x.com", vec![], "t2");
        assert_eq!(reg.default.as_deref(), Some("a@x.com"));
        assert_eq!(reg.accounts["b@x.com"].added, "t2");
    }

    #[test]
    fn upsert_keeps_added_and_replaces_scopes() {
        let mut reg = Registry::default();
        reg.upsert("a@x.com", vec!["s1".into()], "t1");
        reg.upsert("a@x.com", vec!["s1".into(), "s2".into()], "t2");
        assert_eq!(reg.accounts["a@x.com"].added, "t1");
        assert_eq!(reg.accounts["a@x.com"].scopes, vec!["s1", "s2"]);
    }

    #[test]
    fn removing_default_leaves_no_default() {
        let mut reg = registry(&["a@x.com", "b@x.com"], Some("a@x.com"));
        assert!(reg.remove("a@x.com"));
        assert_eq!(reg.default, None);
        assert!(!reg.remove("a@x.com"));
    }

    #[test]
    fn adding_after_default_removed_does_not_set_default() {
        let mut reg = registry(&["b@x.com"], None);
        reg.upsert("c@x.com", vec![], "t");
        assert_eq!(reg.default, None);
    }

    #[test]
    fn set_default_requires_known_account() {
        let mut reg = registry(&["a@x.com"], None);
        assert!(reg.set_default("b@x.com").is_err());
        reg.set_default("a@x.com").unwrap();
        assert_eq!(reg.default.as_deref(), Some("a@x.com"));
    }

    #[test]
    fn merge_scopes_preserves_order_and_dedups() {
        let merged = merge_scopes(
            &["a".to_string(), "b".to_string()],
            &["b".to_string(), "c".to_string()],
        );
        assert_eq!(merged, vec!["a", "b", "c"]);
    }

    #[test]
    fn registry_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Registry::load(dir.path()).unwrap(), None);
        let mut reg = Registry::default();
        reg.upsert("a@x.com", vec!["s1".into()], "2026-10-18T00:00:00Z");
        reg.save(dir.path()).unwrap();
        assert!(Registry::path(dir.path()).exists());
        assert_eq!(Registry::load(dir.path()).unwrap(), Some(reg));
    }

    #[test]
    fn corrupt_registry_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(Registry::path(dir.path()), "default = [").unwrap();
        assert!(Registry::load(dir.path()).is_err());
    }

    // -- flag extraction ----------------------------------------------------

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn split_flag_anywhere() {
        let (rest, value) = split_account_flag(args(&[
            "gws",
            "--account",
            "a@x.com",
            "drive",
            "files",
            "list",
        ]))
        .unwrap();
        assert_eq!(rest, args(&["gws", "drive", "files", "list"]));
        assert_eq!(value.as_deref(), Some("a@x.com"));

        let (rest, value) = split_account_flag(args(&[
            "gws",
            "drive",
            "files",
            "list",
            "--account=a@x.com",
        ]))
        .unwrap();
        assert_eq!(rest, args(&["gws", "drive", "files", "list"]));
        assert_eq!(value.as_deref(), Some("a@x.com"));
    }

    #[test]
    fn split_flag_absent() {
        let (rest, value) = split_account_flag(args(&["gws", "drive"])).unwrap();
        assert_eq!(rest, args(&["gws", "drive"]));
        assert_eq!(value, None);
    }

    #[test]
    fn split_flag_errors() {
        assert!(split_account_flag(args(&["gws", "drive", "--account"])).is_err());
        assert!(split_account_flag(args(&[
            "gws",
            "--account",
            "a@x.com",
            "--account",
            "b@x.com"
        ]))
        .is_err());
        // Repeating the same account is harmless.
        assert!(
            split_account_flag(args(&["gws", "--account", "a@x.com", "--account=A@x.com"])).is_ok()
        );
    }
}
