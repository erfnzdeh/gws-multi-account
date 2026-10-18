---
"@googleworkspace/cli": patch
---

Keep the test encryption key in a per-process temp directory so `cargo test` no longer writes `.encryption_key` into the developer's real `~/.config/gws`
