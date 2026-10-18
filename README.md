<h1 align="center">gws (multi-account fork)</h1>

**One CLI for all of Google Workspace — built for humans and AI agents.**<br>
Drive, Gmail, Calendar, and every Workspace API. Zero boilerplate. Structured JSON output. 40+ agent skills included.

> [!IMPORTANT]
> **This is a fork of [googleworkspace/cli](https://github.com/googleworkspace/cli) that adds [multiple accounts](#multiple-accounts).**
> Sign in to several Google accounts and pick one per command with `--account EMAIL`.
> The fork has no prebuilt binaries, npm package or Homebrew formula. Those all install
> upstream `gws`, which has no `--account` flag. Build this fork from source as shown in
> [Installation](#installation).

> [!NOTE]
> This is **not** an officially supported Google product.

<p>
  <a href="https://github.com/erfnzdeh/gws-multi-account/blob/main/LICENSE"><img src="https://img.shields.io/github/license/erfnzdeh/gws-multi-account" alt="license"></a>
</p>

`gws` doesn't ship a static list of commands. It reads Google's own [Discovery Service](https://developers.google.com/discovery) at runtime and builds its entire command surface dynamically. When Google Workspace adds an API endpoint or method, `gws` picks it up automatically.

> [!IMPORTANT]
> This project is under active development. Expect breaking changes as we march toward v1.0.

## Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Notes for AI agents](#notes-for-ai-agents)
- [Why gws?](#why-gws)
- [Authentication](#authentication)
- [AI Agent Skills](#ai-agent-skills)
- [Advanced Usage](#advanced-usage)
- [Environment Variables](#environment-variables)
- [Exit Codes](#exit-codes)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Prerequisites

- **A Rust toolchain** (stable). See [Installation](#installation).
- **A Google Cloud project with your own OAuth client.** Create it in the [Google Cloud Console](https://console.cloud.google.com/), or let `gws auth setup` create it (needs the [`gcloud` CLI](https://cloud.google.com/sdk/docs/install)). Don't reuse someone else's `client_secret.json` or credentials.
- **A Google account** with access to Google Workspace (a personal `@gmail.com` account works).

## Installation

### 1. Install Rust

Use the official installer from [rustup.rs](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then open a new terminal, or run `. "$HOME/.cargo/env"`, so `cargo` and `~/.cargo/bin` are on your `PATH`.

> [!NOTE]
> Homebrew's `rustup` formula behaves differently: it has no `rustup-init`, you need to run
> `rustup default stable` yourself, and its `cargo` lives in the keg-only
> `$(brew --prefix rustup)/bin`, which is not on `PATH` by default. If you use it, add that
> directory and `~/.cargo/bin` to your `PATH`.

### 2. Build and install the fork

```bash
cargo install --git https://github.com/erfnzdeh/gws-multi-account --locked
```

This builds the `gws` binary and installs it to `~/.cargo/bin/gws`. The first build downloads
about 300 crates and takes a few minutes. Don't add a package name after the URL: the repo
has a single binary package (`google-workspace-cli`), and `gws` is the name of its binary, not
of a package.

To install somewhere else, add `--root`, for example `--root ~/.local` for `~/.local/bin/gws`.
From a local clone, use `cargo install --path crates/google-workspace-cli --locked`.

### 3. Make sure `gws` is the fork

```bash
which -a gws
gws auth list
```

The fork replaces upstream `gws` completely: same binary name, same `gws --version` output,
same config directory. So `--version` can't tell them apart. `gws auth list` can: the fork
prints JSON with an `"accounts"` field (an empty list before your first login), while
upstream has no `auth list` command and fails. If `which -a gws` lists more than one path,
the first one wins. Remove any upstream copies:

```bash
npm uninstall -g @googleworkspace/cli
```

```bash
brew uninstall googleworkspace-cli
```

Also check scripts, cron jobs and launchd agents that call `gws` by an absolute path such as
`/opt/homebrew/bin/gws`. They keep running the old binary, or break once it's removed.
launchd and cron don't load your shell profile, so give them the full path to the fork.

### Updating

```bash
cargo install --git https://github.com/erfnzdeh/gws-multi-account --locked --force
```

On macOS, a rebuilt binary may make Keychain ask again for access to the `gws-cli` entry (see
[Troubleshooting](#macos-keychain-prompt-after-installing-or-updating)).

## Quick Start

```bash
gws auth setup                                      # optional: creates a Cloud project + OAuth client (needs gcloud)
gws auth login --account you@gmail.com -s gmail,drive,calendar,sheets
gws auth login --account you@work.com -s gmail,drive  # add as many accounts as you like
gws auth list                                       # JSON: accounts and the default
gws --account you@work.com drive files list --params '{"pageSize": 5}'
```

The first account you log in to becomes the default for reads. Change it with
`gws auth default EMAIL`. If you already used upstream `gws`, import your existing sign-in
first (see [Coming from upstream gws](#coming-from-upstream-gws)).

## Notes for AI agents

If you are an AI agent installing or using this CLI for someone, these are the mistakes
earlier agents actually made. Read them before you start.

**Installing**

- Don't install `@googleworkspace/cli` from npm, the Homebrew formula, the upstream GitHub
  releases or the upstream Nix flake. They are all upstream `gws` without multi-account
  support. Use the `cargo install --git` command [above](#2-build-and-install-the-fork).
- Run `gws auth list` to confirm the installed `gws` is the fork (it prints JSON with an
  `"accounts"` field). `gws --version` prints the same thing for the fork and upstream, so
  it proves nothing. An old upstream binary earlier on `PATH` is the most common problem.
- Don't guess a package name for `cargo install`. The plain command above is correct.
- Building and logging in need the user: the OAuth consent screen opens in their browser,
  and macOS may show a Keychain prompt that only a person can approve. Tell them what to
  expect, then wait.

**Logging in**

- Each person needs their own OAuth client in their own Google Cloud project. Never copy
  another person's `client_secret.json`, `credentials.enc`, `.encryption_key` or token files.
- With an unverified (testing mode) app, always pass `-s` with the services the user needs
  (e.g. `-s gmail,drive,calendar,sheets`). The scope picker's `recommended` preset and
  `--full` both go past Google's limit of about 25 scopes for unverified apps, and the consent
  screen fails.
- `gws auth login` listens on a new random `localhost` port each time. If you run it again,
  only the newest URL works. Login finishes when the browser reaches the localhost page, so
  the user must click through to the end.
- Pass `--account EMAIL` to `gws auth login`. If the user picks a different Google account
  in the browser, nothing is saved, and the error says so.
- If `~/.config/gws` already holds an upstream sign-in, `--account` fails with
  `noAccountRegistry`. Run `gws auth import --from ~/.config/gws` once, then continue.

**Choosing the account**

- Run `gws auth list` before anything else and use only the emails it returns. Never invent
  or guess an address.
- With two or more accounts, every write (send, create, update, delete, share) needs
  `--account EMAIL`, or it fails with `"reason": "accountRequired"` and exit code 3. The
  error lists the configured accounts. If the request doesn't say which account to use, ask
  the user. Don't pick the default for them.
- Reads without `--account` use the default account and print
  `gws: using default account EMAIL` on stderr. A question like "how many unread emails do
  I have?" may mean every account: run one command per account from `gws auth list`, or ask.
- Use `--account`, not a separate `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` per account. That older
  workaround needed a matching `GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND` for every directory and
  was easy to get wrong.

**Running commands**

- stdout is JSON. Notes such as `Using keyring backend: keyring` and
  `gws: using default account ...` go to stderr. Don't pipe `2>&1` into a JSON parser.
- Don't send a write's output to `/dev/null`. Errors like `accountRequired` arrive on
  stdout and stderr, and hiding them makes a failed write look like it worked.
- After a write, read the result back. A write that reported an error may still have been
  applied, so check the current state before retrying, or you may create duplicates.
- Some writes have side effects. For example, `drive permissions create` emails the person
  you share with unless you pass `"sendNotificationEmail": false` in `--params`.
- Use `--dry-run` to check a request without sending it.

## Why gws?

**For humans** — stop writing `curl` calls against REST docs. `gws` gives you `--help` on every resource, `--dry-run` to preview requests, and auto‑pagination.

**For AI agents** — every response is structured JSON. Pair it with the included agent skills and your LLM can manage Workspace without custom tooling.

```bash
# List the 10 most recent files
gws drive files list --params '{"pageSize": 10}'

# Create a spreadsheet
gws sheets spreadsheets create --json '{"properties": {"title": "Q1 Budget"}}'

# Send a Chat message
gws chat spaces messages create \
  --params '{"parent": "spaces/xyz"}' \
  --json '{"text": "Deploy complete."}' \
  --dry-run

# Introspect any method's request/response schema
gws schema drive.files.list

# Stream paginated results as NDJSON
gws drive files list --params '{"pageSize": 100}' --page-all | jq -r '.files[].name'
```

## Authentication

The CLI supports multiple auth workflows so it works on your laptop, in CI, and on a server.

### Which setup should I use?

| I have… | Use |
|---|---|
| `gcloud` installed and authenticated | [`gws auth setup`](#interactive-local-desktop) (fastest) |
| A GCP project but no `gcloud` | [Manual OAuth setup](#manual-oauth-setup-google-cloud-console) |
| An existing OAuth access token | [`GOOGLE_WORKSPACE_CLI_TOKEN`](#pre-obtained-access-token) |
| Existing Credentials | [`GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE`](#service-account-server-to-server) |

### Interactive (local desktop)

Credentials are encrypted at rest (AES-256-GCM) with the key stored in your OS keyring (or `~/.config/gws/.encryption_key` when `GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND=file`).

```bash
gws auth setup       # one-time: creates a Cloud project, enables APIs, logs you in
gws auth login       # subsequent scope selection and login
```

> `gws auth setup` requires the [`gcloud` CLI](https://cloud.google.com/sdk/docs/install). If you don't have `gcloud`, use the [manual setup](#manual-oauth-setup-google-cloud-console) below instead.

> [!WARNING]
> **Scope limits in testing mode:** If your OAuth app is unverified (testing mode),
> Google limits consent to ~25 scopes. The `recommended` scope preset includes 85+
> scopes and **will fail** for unverified apps (especially for `@gmail.com` accounts).
> Choose individual services instead to filter the scope picker:
> ```bash
> gws auth login -s drive,gmail,sheets
> ```


### Manual OAuth setup (Google Cloud Console)

Use this when `gws auth setup` cannot automate project/client creation, or when you want explicit control.

1. Open Google Cloud Console in the target project:
   - OAuth consent screen: `https://console.cloud.google.com/apis/credentials/consent?project=<PROJECT_ID>`
   - Credentials: `https://console.cloud.google.com/apis/credentials?project=<PROJECT_ID>`
2. Configure OAuth branding/audience if prompted:
   - App type: **External** (testing mode is fine)
3. Add your account under **Test users**
4. Create an OAuth client:
   - Type: **Desktop app**
5. Download the client JSON and save it to:
   - `~/.config/gws/client_secret.json`

> [!IMPORTANT]
> **You must add yourself as a test user.** In the OAuth consent screen, click
> **Test users → Add users** and enter your Google account email. Without this,
> login will fail with a generic "Access blocked" error.

Then run:

```bash
gws auth login
```

### Browser-assisted auth (human or agent)

You can complete OAuth either manually or with browser automation.

- **Human flow**: run `gws auth login`, open the printed URL, approve scopes.
- **Agent-assisted flow**: the agent opens the URL, selects account, handles consent prompts, and returns control once the localhost callback succeeds.

If consent shows **"Google hasn't verified this app"** (testing mode), click **Continue**.
If scope checkboxes appear, select required scopes (or **Select all**) before continuing.

### Headless / CI (export flow)

1. Complete interactive auth on a machine with a browser.
2. Export credentials:
   ```bash
   gws auth export --unmasked > credentials.json
   ```
3. On the headless machine:
   ```bash
   export GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE=/path/to/credentials.json
   gws drive files list   # just works
   ```

### Service Account (server-to-server)

Point to your key file; no login needed.

```bash
export GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE=/path/to/service-account.json
gws drive files list
```

### Pre-obtained Access Token

Useful when another tool (e.g. `gcloud`) already mints tokens for your environment.

```bash
export GOOGLE_WORKSPACE_CLI_TOKEN=$(gcloud auth print-access-token)
```

### Precedence

| Priority | Source                 | Set via                                 |
| -------- | ---------------------- | --------------------------------------- |
| 1        | Access token           | `GOOGLE_WORKSPACE_CLI_TOKEN`            |
| 2        | Credentials file       | `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE` |
| 3        | Encrypted credentials  | `gws auth login`                        |
| 4        | Plaintext credentials  | `~/.config/gws/credentials.json`        |

Environment variables can also live in a `.env` file.

### Multiple accounts

`gws` can hold credentials for several Google accounts. Each command runs as
exactly one of them, chosen by `--account EMAIL` (accepted anywhere on the
command line), then `GOOGLE_WORKSPACE_CLI_ACCOUNT`, then the default account.

```bash
gws auth login --account me@gmail.com      # the first account becomes the default
gws auth login --account me@work.com       # pre-selects it in the browser
gws auth list                              # JSON: accounts and the default
gws auth default me@work.com

gws --account me@work.com gmail +triage
gws calendar +agenda                       # reads use the default account
```

Rules, designed so agents can't act as the wrong account by accident:

- **Writes must name an account.** With two or more accounts configured, a
  command that changes data (any method that isn't a GET and doesn't accept a
  `.readonly` scope, or a writing helper such as `+send`) fails with
  `"reason": "accountRequired"` unless `--account` or
  `GOOGLE_WORKSPACE_CLI_ACCOUNT` is set. The error lists the configured
  accounts. `--dry-run` is exempt.
- **Reads fall back to the default**, with a `gws: using default account ...`
  note on stderr. Stdout is unchanged.
- **No fallbacks between identities.** An unknown account is an error, and so
  is combining `--account` with `GOOGLE_WORKSPACE_CLI_TOKEN` or
  `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE`.
- **Logging in again adds scopes** (incremental auth) instead of replacing
  them. If the browser returns a different account than `--account`, nothing
  is saved.
- **Per-account OAuth clients.** `gws auth login --account me@work.com
  --client-secret ./client.json` pins a client to one account, for Workspace
  orgs that block external apps. Everyone else shares `client_secret.json`.
- `gws auth logout --account X` deletes that account locally; add `--revoke`
  to also revoke its refresh token at Google.

Accounts live in `~/.config/gws/accounts.toml` and
`~/.config/gws/accounts/<email>/` (credentials, token cache, timezone cache),
all encrypted with the same key.

### Coming from upstream gws

The fork uses the same binary name, config directory (`~/.config/gws`), Keychain entry and
environment variables as upstream, so an existing upstream sign-in keeps working as a
single-account directory, exactly as before. Until you import it, `--account` fails with
`noAccountRegistry`. To move it into the registry:

```bash
gws auth import --from ~/.config/gws                          # this directory, in place
gws auth import --from ~/.config/gws-work --keyring-backend file
```

Importing in place renames the old top-level files to `*.imported-<timestamp>` instead of
deleting them. Importing from another directory leaves that directory untouched. `import`
refuses an account that is already configured. Log it out first if you really want to
replace it.

## AI Agent Skills

The repo ships 100+ Agent Skills (`SKILL.md` files) — one for every supported API, plus higher-level helpers for common workflows and 50 curated recipes for Gmail, Drive, Docs, Calendar, and Sheets. See the full [Skills Index](docs/skills.md) for the complete list.

Install the skills from this fork, not from upstream. Only the fork's copies include the
`gws-accounts` skill and the `--account` notes in `gws-shared`.

```bash
# Install all skills at once
npx skills add https://github.com/erfnzdeh/gws-multi-account

# Or pick only what you need (keep gws-shared and gws-accounts)
npx skills add https://github.com/erfnzdeh/gws-multi-account/tree/main/skills/gws-shared
npx skills add https://github.com/erfnzdeh/gws-multi-account/tree/main/skills/gws-accounts
npx skills add https://github.com/erfnzdeh/gws-multi-account/tree/main/skills/gws-gmail
```

The skills don't install the CLI. Install it first (see [Installation](#installation)).

<details>
<summary>OpenClaw setup</summary>

```bash
# Symlink all skills (stays in sync with repo)
ln -s $(pwd)/skills/gws-* ~/.openclaw/skills/

# Or copy specific skills
cp -r skills/gws-drive skills/gws-gmail ~/.openclaw/skills/
```

Install the CLI yourself first. Don't let a skill manager auto-install `@googleworkspace/cli` from npm: that is upstream `gws`, without `--account`.

</details>

## Gemini CLI Extension

1. Authenticate the CLI first:

   ```bash
   gws auth setup
   ```

2. Install the extension into the Gemini CLI:
   ```bash
   gemini extensions install https://github.com/erfnzdeh/gws-multi-account
   ```

Installing this extension gives your Gemini CLI agent direct access to all `gws` commands and Google Workspace agent skills. Because `gws` handles its own authentication securely, you simply need to authenticate your terminal once prior to using the agent, and the extension will automatically inherit your credentials.

## Advanced Usage

### Multipart Uploads

```bash
gws drive files create --json '{"name": "report.pdf"}' --upload ./report.pdf
```

### Pagination

| Flag                | Description                                    | Default |
| ------------------- | ---------------------------------------------- | ------- |
| `--page-all`        | Auto-paginate, one JSON line per page (NDJSON) | off     |
| `--page-limit <N>`  | Max pages to fetch                             | 10      |
| `--page-delay <MS>` | Delay between pages                            | 100 ms  |

### Google Sheets — Shell Escaping

Sheets ranges use `!` which bash interprets as history expansion. Always wrap values in **single quotes**:

```bash
# Read cells A1:C10 from "Sheet1"
gws sheets spreadsheets values get \
  --params '{"spreadsheetId": "SPREADSHEET_ID", "range": "Sheet1!A1:C10"}'

# Append rows
gws sheets spreadsheets values append \
  --params '{"spreadsheetId": "ID", "range": "Sheet1!A1", "valueInputOption": "USER_ENTERED"}' \
  --json '{"values": [["Name", "Score"], ["Alice", 95]]}'
```

### Helper Commands

Some services ship hand-crafted helper commands alongside the auto-generated Discovery surface. Helper commands are prefixed with `+` so they are visually distinct and never collide with Discovery-generated method names.

Time-aware helpers (`+agenda`, `+standup-report`, `+weekly-digest`, `+meeting-prep`) automatically use your **Google account timezone** (fetched from Calendar Settings API and cached for 24 hours). Override with `--timezone`/`--tz` on `+agenda`, or set the `--timezone` flag for explicit control.

Run `gws <service> --help` to see both Discovery methods and helper commands together.

```bash
gws gmail --help      # shows +send, +reply, +reply-all, +forward, +triage, +watch …
gws calendar --help   # shows +insert, +agenda …
gws drive --help      # shows +upload …
```

**Full helper reference:**

| Service | Command | Description |
|---------|---------|-------------|
| `gmail` | `+send` | Send an email |
| `gmail` | `+reply` | Reply to a message (handles threading automatically) |
| `gmail` | `+reply-all` | Reply-all to a message |
| `gmail` | `+forward` | Forward a message to new recipients |
| `gmail` | `+triage` | Show unread inbox summary (sender, subject, date) |
| `gmail` | `+watch` | Watch for new emails and stream them as NDJSON |
| `sheets` | `+append` | Append a row to a spreadsheet |
| `sheets` | `+read` | Read values from a spreadsheet |
| `docs` | `+write` | Append text to a document |
| `chat` | `+send` | Send a message to a space |
| `drive` | `+upload` | Upload a file with automatic metadata |
| `calendar` | `+insert` | Create a new event |
| `calendar` | `+agenda` | Show upcoming events (uses Google account timezone; override with `--timezone`) |
| `script` | `+push` | Replace all files in an Apps Script project with local files |
| `workflow` | `+standup-report` | Today's meetings + open tasks as a standup summary |
| `workflow` | `+meeting-prep` | Prepare for your next meeting: agenda, attendees, and linked docs |
| `workflow` | `+email-to-task` | Convert a Gmail message into a Google Tasks entry |
| `workflow` | `+weekly-digest` | Weekly summary: this week's meetings + unread email count |
| `workflow` | `+file-announce` | Announce a Drive file in a Chat space |
| `events` | `+subscribe` | Subscribe to Workspace events and stream them as NDJSON |
| `events` | `+renew` | Renew/reactivate Workspace Events subscriptions |
| `modelarmor` | `+sanitize-prompt` | Sanitize a user prompt through a Model Armor template |
| `modelarmor` | `+sanitize-response` | Sanitize a model response through a Model Armor template |
| `modelarmor` | `+create-template` | Create a new Model Armor template |

**Examples:**

```bash
# Send an email
gws gmail +send --to alice@example.com --subject "Hello" --body "Hi there"

# Reply to a message
gws gmail +reply --message-id MESSAGE_ID --body "Thanks!"

# Append a row to a spreadsheet
gws sheets +append --spreadsheet SPREADSHEET_ID --values "Alice,95"

# Show today's calendar agenda
gws calendar +agenda

# Upload a file to Drive
gws drive +upload ./report.pdf --name "Q1 Report"

# Morning standup summary
gws workflow +standup-report

# Show today's agenda in a specific timezone
gws calendar +agenda --today --timezone America/New_York
```

### Model Armor (Response Sanitization)

Integrate [Google Cloud Model Armor](https://cloud.google.com/security/products/model-armor) to scan API responses for prompt injection before they reach your agent.

```bash
gws gmail users messages get --params '...' \
  --sanitize "projects/P/locations/L/templates/T"
```

| Variable                                 | Description                  |
| ---------------------------------------- | ---------------------------- |
| `GOOGLE_WORKSPACE_CLI_SANITIZE_TEMPLATE` | Default Model Armor template |
| `GOOGLE_WORKSPACE_CLI_SANITIZE_MODE`     | `warn` (default) or `block`  |

## Environment Variables

All variables are optional. See [`.env.example`](.env.example) for a copy-paste template.

| Variable | Description |
|---|---|
| `GOOGLE_WORKSPACE_CLI_TOKEN` | Pre-obtained OAuth2 access token (highest priority) |
| `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE` | Path to OAuth credentials JSON (user or service account) |
| `GOOGLE_WORKSPACE_CLI_ACCOUNT` | Account to use when `--account` is not given (see [Multiple accounts](#multiple-accounts)) |
| `GOOGLE_WORKSPACE_CLI_CLIENT_ID` | OAuth client ID (alternative to `client_secret.json`) |
| `GOOGLE_WORKSPACE_CLI_CLIENT_SECRET` | OAuth client secret (paired with `CLIENT_ID`) |
| `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` | Override config directory (default: `~/.config/gws`) |
| `GOOGLE_WORKSPACE_CLI_SANITIZE_TEMPLATE` | Default Model Armor template |
| `GOOGLE_WORKSPACE_CLI_SANITIZE_MODE` | `warn` (default) or `block` |
| `GOOGLE_WORKSPACE_CLI_LOG` | Log level for stderr (e.g., `gws=debug`). Off by default. |
| `GOOGLE_WORKSPACE_CLI_LOG_FILE` | Directory for JSON log files with daily rotation. Off by default. |
| `GOOGLE_WORKSPACE_PROJECT_ID` | GCP project ID override for quota/billing and fallback for helper commands |

Environment variables can also be set in a `.env` file (loaded via [dotenvy](https://crates.io/crates/dotenvy)).

## Exit Codes

`gws` uses structured exit codes so scripts can branch on the failure type without parsing error output.

| Code | Meaning | Example cause |
|------|---------|---------------|
| `0` | Success | Command completed normally |
| `1` | API error | Google returned a 4xx/5xx response |
| `2` | Auth error | Credentials missing, expired, or invalid |
| `3` | Validation error | Bad arguments, unknown service, invalid flag |
| `4` | Discovery error | Could not fetch the API schema document |
| `5` | Internal error | Unexpected failure |

```bash
gws drive files list --params '{"fileId": "bad"}'
echo $?   # 1 — API error

gws unknown-service files list
echo $?   # 3 — validation error (unknown service)
```

## Architecture

`gws` uses a **two-phase parsing** strategy:

1. Read `argv[1]` to identify the service (e.g. `drive`)
2. Fetch the service's Discovery Document (cached 24 h)
3. Build a `clap::Command` tree from the document's resources and methods
4. Re-parse the remaining arguments
5. Authenticate, build the HTTP request, execute

All output — success, errors, download metadata — is structured JSON.

## Troubleshooting

### "Access blocked" or 403 during login

Your OAuth app is in **testing mode** and your account is not listed as a test user.

**Fix:** Open the [OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent) in your GCP project → **Test users** → **Add users** → enter your Google account email. Then retry `gws auth login`.

### "Google hasn't verified this app"

Expected when your app is in testing mode. Click **Advanced** → **Go to \<app name\> (unsafe)** to proceed. This is safe for personal use; verification is only required to publish the app to other users.

### Too many scopes / consent screen error

Unverified (testing mode) apps are limited to ~25 OAuth scopes. The `recommended` scope preset includes many scopes and will exceed this limit.

**Fix:** Select only the scopes you need:

```bash
gws auth login --scopes drive,gmail,calendar
```

### `gcloud` CLI not found

`gws auth setup` requires the `gcloud` CLI to automate project creation. You have three options:

1. [Install gcloud](https://cloud.google.com/sdk/docs/install) and use `gcloud` directly.
2. Re-run `gws auth setup` which wraps `gcloud` calls.
3. Skip `gcloud` entirely — set up OAuth credentials manually in the [Cloud Console](#manual-oauth-setup-google-cloud-console)

### `redirect_uri_mismatch`

The OAuth client was not created as a **Desktop app** type. In the [Credentials](https://console.cloud.google.com/apis/credentials) page, delete the existing client, create a new one with type **Desktop app**, and download the new JSON.

### API not enabled — `accessNotConfigured`

If a required Google API is not enabled for your GCP project, you will see a
403 error with reason `accessNotConfigured`:

```json
{
  "error": {
    "code": 403,
    "message": "Gmail API has not been used in project 549352339482 ...",
    "reason": "accessNotConfigured",
    "enable_url": "https://console.developers.google.com/apis/api/gmail.googleapis.com/overview?project=549352339482"
  }
}
```

`gws` also prints an actionable hint to **stderr**:

```
💡 API not enabled for your GCP project.
   Enable it at: https://console.developers.google.com/apis/api/gmail.googleapis.com/overview?project=549352339482
   After enabling, wait a few seconds and retry your command.
```

**Steps to fix:**

1. Click the `enable_url` link (or copy it from the `enable_url` JSON field).
2. In the GCP Console, click **Enable**.
3. Wait ~10 seconds, then retry your `gws` command.

> [!TIP]
> You can also run `gws auth setup` which walks you through enabling all required
> APIs for your project automatically.

### `--account` is not recognized

You are running upstream `gws`, not this fork. Check `which -a gws` and `gws auth list`
(only the fork has `auth list`), then remove or shadow the other copy. See
[Make sure gws is the fork](#3-make-sure-gws-is-the-fork).

### `accountRequired`

The command writes data, two or more accounts are configured, and none was named. Rerun it
with `--account EMAIL` (or set `GOOGLE_WORKSPACE_CLI_ACCOUNT`), using one of the emails in
`error.accounts`. `--dry-run` never fails this way.

### `noAccountRegistry`

The config directory still holds a single upstream sign-in. Run
`gws auth import --from ~/.config/gws`, then use `--account`. See
[Coming from upstream gws](#coming-from-upstream-gws).

### `Could not decrypt ... The file was left untouched`

The credentials were written with a different keyring backend (`keyring` or `file`) than
the one in use now. Set `GOOGLE_WORKSPACE_CLI_KEYRING_BACKEND` to match, or run
`gws auth login --account EMAIL` to replace them. Unlike upstream, the fork never deletes a
credentials file it can't decrypt.

### macOS Keychain prompt after installing or updating

The encryption key is stored in the login Keychain under the service `gws-cli`. A newly
built binary isn't signed, so macOS may ask whether `gws` may use that entry. Click
**Always Allow**. An agent running `gws` in the background waits until someone clicks it.

The Keychain account name is `$USER`. If you run `gws` from launchd, cron or another
environment, make sure `USER` is set to the same value, or it won't find the key.

### 403 for a second person using your OAuth client

`gws` bills API calls to the OAuth client's Cloud project. If someone else signs in with a
client from your project, their calls fail with 403 until their account may use that
project. Either have them create their own client (recommended), or grant them access:

```bash
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=user:them@example.com \
  --role=roles/serviceusage.serviceUsageConsumer --condition=None
```

### Login stopped working after about a week

OAuth apps in **Testing** mode get refresh tokens that expire after 7 days. Run
`gws auth login --account EMAIL` again, or set the app's publishing status to
**In production** on the OAuth consent screen (you'll still see the "unverified app" warning,
which is fine for personal use).

### `gws auth login` never finishes

Each login listens on a new random `localhost` port. Use the URL from the most recent run and
continue in the browser until it shows a localhost page saying "Success! You may now close this
window."

## Development

```bash
cargo build                       # dev build
cargo clippy -- -D warnings       # lint
cargo test                        # unit tests
./scripts/coverage.sh             # HTML coverage report → target/llvm-cov/html/
```

## License

Apache-2.0

## Disclaimer

> [!CAUTION]
> This is **not** an officially supported Google product.
