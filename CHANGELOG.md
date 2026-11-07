# Changelog

## 0.1.1 - Unreleased

- `hushhook explain <rule-id>`: shows where a rule lives, how to turn it off, and a ready link to report a wrong match (only the rule id goes in the link).
- When a read or command is blocked, the message now tells the agent that the user can run `hushhook explain <rule-id>`.
- `hushhook rules new <kind> <id>`: creates a starter file for a rule of your own and makes sure your config loads it.
- `hushhook rules share <id>`: checks your examples and, if they pass and hold no real-looking secret, prints a link so others using the service get the rule too.
- New secret rules for Notion integration tokens (`ntn_`) and legacy integration tokens (`secret_`); ordinary identifiers such as `secret_key_base` stay unmasked.

## 0.1.0 - Unreleased

First release.

- Claude Code hooks: before each Read and Bash call, and after every tool.
- `hushhook mask`: masks secrets line by line without buffering the whole input.
- Rule packs in plain text: 40+ secret formats, 30 sensitive file kinds and 20 dangerous command patterns.
- `hushhook install` and `uninstall`: merge into Claude Code settings with a backup, and can run repeatedly.
- `hushhook doctor`, `rules`, `rules test` and `leaks`.
- `hushhook map`, `peek`, `refs` and `doc` for Python, shell and Go.
- Claude Code plugin packaging.
