# Security

## Reporting a problem

Please report security problems privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. This opens a private security advisory, visible only to you and the maintainers.

Please do not open a public issue for these, and leave real secrets out of your report. A made-up example of the same shape is all we need.

## What counts

- hushhook sends data somewhere, or writes a secret value to its log or to any file.
- A way to run code through hushhook's rule files, config or hook input.
- `hushhook install` or `uninstall` damaging settings they should have left alone.
- A hook failure that stops the agent's session instead of letting it carry on.
- A secret slipping past hushhook in a way the README's "What it cannot stop" section does not describe.

## What does not count

The limits listed in that section of the README are known and expected. hushhook is built to reduce accidents, and it is not a sandbox. A missing token format is also not a security problem: please add a rule, or open a regular issue.

## Supported versions

Fixes go into the latest release.
