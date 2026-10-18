---
"@googleworkspace/cli": minor
---

Add multi-account support: a global `--account EMAIL` flag and `GOOGLE_WORKSPACE_CLI_ACCOUNT`, `gws auth list`, `gws auth default`, `gws auth import`, per-account credentials and token caches (fixing stale tokens after switching accounts, #780), and a rule that commands which change data must name an account when several are configured. Undecryptable credentials are no longer deleted.
