---
name: gws-accounts
description: "gws CLI: Choosing the right Google account when several are configured."
metadata:
  version: 0.22.5
  openclaw:
    category: "productivity"
    requires:
      bins:
        - gws
---

# gws: Multiple Accounts

> **PREREQUISITE:** Read `../gws-shared/SKILL.md` for auth, global flags, and security rules.

`gws` can hold credentials for several Google accounts. Each command runs as
exactly one of them.

## Rules

1. Run `gws auth list` first to see the configured accounts and the default.
2. Pass `--account EMAIL` on every command that changes data (send, create,
   update, delete, share). With more than one account configured, gws refuses
   such commands without it.
3. Never guess the account. If the user's request doesn't make it clear, ask.
4. Reads may omit `--account`; they use the default account, and gws prints
   `gws: using default account EMAIL` on stderr when it does.
5. To work across accounts (e.g. check two inboxes), run one command per
   account. There is no multi-account fan-out.

## Selecting an account

```bash
gws auth list                                        # accounts + default
gws --account me@work.com gmail +triage              # flag, anywhere in argv
GOOGLE_WORKSPACE_CLI_ACCOUNT=me@work.com gws drive files list
```

The flag overrides `GOOGLE_WORKSPACE_CLI_ACCOUNT`, which overrides the default.
Matching is exact and case-insensitive.

## Errors

Account errors come back as JSON with exit code 3. `error.accounts` lists the
configured emails, so retry with one of them:

| `error.reason` | Meaning |
|---|---|
| `accountRequired` | A write (or a read with no default) needs `--account` |
| `unknownAccount` | The email isn't configured |
| `accountConflict` | `--account` was combined with `GOOGLE_WORKSPACE_CLI_TOKEN` or `..._CREDENTIALS_FILE` |
| `noAccountRegistry` | This config directory has a single, unnamed account |
| `accountMismatch` | `auth login --account X` signed in to a different Google account |

## Managing accounts

```bash
gws auth login --account me@work.com                 # add, or add scopes to, an account
gws auth login --account me@work.com --client-secret ./org_client.json
gws auth default me@work.com                         # default for reads
gws auth status --account me@work.com
gws auth logout --account me@work.com [--revoke]
gws auth import --from ~/.config/gws-old [--keyring-backend file]
```

Logging in again to an existing account adds the new scopes to the ones it
already has.
