# Contributing

The most useful thing you can add to hushhook is a rule. It takes about five minutes, needs no knowledge of the code, and from then on it protects everyone who uses hushhook. You do not need to install anything beyond Python 3.9 or newer.

## Add a rule in five minutes

Fastest path, no clone needed: `hushhook rules new secrets acme-token` creates a starter file, you fill in the pattern and examples, `hushhook rules test` checks them, and `hushhook rules share acme-token` prints a link that opens the rule on GitHub ready to submit. Prefer a pull request? The steps below do the same by hand.

### 1. Get the code

Fork the repository on GitHub, then:

```bash
git clone https://github.com/YOUR-NAME/hushhook
cd hushhook
git checkout -b add-acme-token
```

### 2. Pick the file

Rules are plain text files in `hushhook/rules/`:

| You want to... | Folder | Files |
| --- | --- | --- |
| Mask a token or key format | `hushhook/rules/secrets/` | `ai`, `chat`, `cloud`, `generic`, `git-hosting`, `messaging`, `package-registries`, `payments` |
| Stop reads of a sensitive file | `hushhook/rules/files/` | `cloud`, `dev-tools`, `env`, `keys` |
| Stop a dangerous command | `hushhook/rules/commands/` | `cloud`, `containers`, `database`, `git`, `shell` |

If nothing fits, create a new file named after the ecosystem, such as `hushhook/rules/secrets/analytics.rules`. Use lowercase letters, digits and hyphens. It gets loaded automatically.

### 3. Write the rule

Add a paragraph at the end of the file, with a blank line before it.

**A secret format:**

```text
id: acme-api-key
pattern: \backme_[A-Za-z0-9]{32}\b
matches: acme_{a*32}
ignores: acme_short
```

**A sensitive file:**

```text
id: acme-credentials
glob: .acme/credentials
matches: ~/.acme/credentials
ignores: docs/acme/credentials.md
```

**A dangerous command:**

```text
id: acme-delete-all
pattern: \backme\s+delete\s+--all\b
reason: this deletes every project in the account.
matches: acme delete --all
ignores: acme delete one-project
```

That is the whole format. Each line is `field: value`. Whatever comes after the colon is taken exactly as written, so there is nothing to escape. Lines starting with `#` are comments.

| Field | Used in | Meaning |
| --- | --- | --- |
| `id` | all | A unique name, in lowercase words joined by hyphens. It appears in the `[hushhook:<id>]` marker. |
| `pattern` | secrets, commands | A [Python regular expression](https://docs.python.org/3/library/re.html). |
| `glob` | files | A file name such as `*.pem`, or the end of a path such as `.aws/credentials`. Repeat the line for more. |
| `except` | files | A name to leave alone, such as `.env.example`. Repeat the line for more. |
| `reason` | commands | One sentence for the agent on why this is stopped. Start with a lowercase letter, since it follows "hushhook blocked this command:". |
| `matches` | all | An example the rule must catch. Repeat the line for more. |
| `ignores` | all | A near miss the rule must leave alone. Repeat the line for more. |
| `body` | secrets | Rarely needed: a pattern for the lines after a match, for secrets that span several lines. See `pem-private-key`. |

**Never paste a real token, not even an expired one.** Write examples with the `{a*32}` shorthand, which means "the text `a` repeated 32 times". The tests expand it when they run, so the repository never holds anything that looks like a real token and GitHub will not refuse your push. You can repeat more than one character: `{a1*16}` gives `a1a1a1...`, handy for a format that needs digits.

### 4. Check it

```bash
python3 -m hushhook rules test
python3 -m unittest discover -s tests
```

The first command prints `all examples pass` when your examples behave. If not, it tells you what to fix:

| Message | What it means |
| --- | --- |
| `should match but does not: acme_{a*32}` | The pattern missed your example. Check the length and the characters. |
| `should not match but does: acme_short` | The pattern is too loose, or the example is not a near miss. |
| `missing matches` | The rule needs at least one example. |
| `has a bad regular expression` | Python could not read the pattern. The message says where. |

To run one test file, use `python3 -m unittest discover -s tests -p 'test_rules.py'`.

### 5. Send it

```bash
git add hushhook/rules
git commit -m "Add Acme API key rule"
git push origin add-acme-token
```

Then open a pull request on GitHub. The automated checks run the same commands on every supported Python version. A link to the service's documentation in the description makes the review much faster.

## What makes a good rule

- **Secrets need a distinctive shape.** A prefix like `ghp_` is ideal. A bare 32-character hex string matches every checksum in a log, so it needs context around it, as in `twilio-auth-token`.
- **A wrong mask costs something too.** Masked text can confuse the agent, so a rule that fires on ordinary output does more harm than good. Your `ignores:` line is where you show the near miss you thought about.
- **Use `\b` at the edges** so the pattern does not fire in the middle of a longer word. If the format can end in `-`, use `(?![A-Za-z0-9_-])` at the end instead.
- **Keep the context visible.** Wrap the sensitive part in `(?P<secret>...)` and only that part gets masked, as in `database-url-password`.
- **Keep patterns simple.** They run on every line of output. Nested repeats such as `(a+)+` can stall on long lines, and a test checks for that.
- **Command rules should only stop things that are hard to undo.** A rule that gets in the way of everyday work ends up turned off.

## Other ways to help

**A new language for the code tools.** `hushhook/codemap.py` covers Python, shell and Go. To add one, give `LANGUAGES` an entry and write the outline and quiet functions for it. A careful regular expression is fine, and the standard library is all you have to work with.

**A new agent.** An adapter is one small file that turns an agent's hook format into calls to `gate.py` and `scan.py`:

1. Copy `hushhook/adapters/claude_code.py` to `hushhook/adapters/<agent>.py`, keeping `handle(event, payload)`.
2. Register it in `ADAPTERS` in `hushhook/adapters/__init__.py`.
3. Add a test file based on `tests/test_hook.py`, and mention the agent in the README.

Run it with `python3 -m hushhook.hook pre --agent <agent>`.

**Bug reports.** If a rule fires on ordinary output, or misses a format, open an issue with what you saw. Please describe the token's shape and leave the real value out. For anything that lets a secret past hushhook in a way the README does not list, see [SECURITY.md](SECURITY.md).

## Project rules

- The standard library only. hushhook has no dependencies, and that is part of why people can trust it.
- Python 3.9 is the oldest supported version.
- A hook must never break the agent's session. Any error means carrying on quietly.
- Nothing leaves the machine, and the log never holds a secret value.
- Add a line to `CHANGELOG.md` for anything a user would notice.
