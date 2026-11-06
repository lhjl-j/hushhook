# hushhook

hushhook keeps secrets and big dumps out of your AI coding agent's conversation. It runs locally, has no dependencies and sends nothing anywhere.

Claude Code is the first supported agent. The core knows nothing about any one agent, so others can plug in through a small adapter.

*hushhook is an independent, unofficial project. It is not made by, affiliated with or endorsed by Anthropic.*

[繁體中文說明](README.zh-TW.md)

## Why

Everything your agent reads, and everything a command prints, becomes part of the conversation and goes to your model provider. That is how these tools work, and most of the time it is exactly what you want. But one `cat .env` or one verbose log can carry a live API key along with it, and once sent, you cannot take it back.

hushhook sits between the agent and its tools and catches the common cases before they reach the model:

- **Masks secrets in tool output.** 40+ known formats (AWS, GitHub, GitLab, Slack, Stripe, OpenAI, Anthropic, JWTs, private keys, database URLs and more) become `[hushhook:<rule-id>]`.
- **Stops reads of sensitive files.** `.env`, private keys, cloud credentials, `.npmrc`, `terraform.tfstate` and 30 kinds in all.
- **Stops big dumps.** A 5,000-line log costs you context and hides the part that matters. The agent gets told how to narrow it.
- **Blocks dangerous commands.** Piping a download into a shell, wiping a home folder, force pushes, `terraform destroy` and 20 patterns in all, each with a plain reason.
- **Lets the agent look at code cheaply.** `hushhook map` shows the outline of a file, `hushhook peek` shows one function, so it reads less to learn the same thing.

Your agent gets a clear explanation each time, so it can adjust and carry on without you stepping in.

## 30-second install

You need Python 3.9 or newer. Nothing else gets installed.

**As a Claude Code plugin:**

```text
/plugin marketplace add monarchsofchaos004-gif/hushhook
/plugin install hushhook@hushhook
```

**As a command line tool:**

```bash
pipx install git+https://github.com/monarchsofchaos004-gif/hushhook
hushhook install     # adds the hooks to ~/.claude/settings.json, with a backup
hushhook doctor      # checks that everything works
```

Use `hushhook install --project` to set it up for one project instead. It records paths from your machine, so keep that change out of your commits. Start a new Claude Code session afterwards. `hushhook uninstall` removes only what it added.

## What it looks like

The agent tries to read an environment file:

```text
$ cat .env
hushhook blocked reading .env (rule dotenv): this file usually holds secrets.
Ask the user for the specific value you need.
```

A command prints something it should not:

```text
$ env | grep -E 'TOKEN|DATABASE'
GITHUB_TOKEN=[hushhook:github-classic-token]
DATABASE_URL=postgres://app:[hushhook:database-url-password]@db.example.com/app
```

The agent reaches for a huge log:

```text
$ cat build.log
hushhook stopped a big dump: build.log has more than 300 lines. Narrow it first:
read a range, search with grep, or run `hushhook map build.log` for an outline
of a Python or shell file.
```

The agent tries something you cannot undo:

```text
$ git push --force origin main
hushhook blocked this command (rule git-force-push): a force push can overwrite
other people's commits. Use --force-with-lease, or ask the user. If it is really
intended, ask the user to run it.
```

If a secret still shows up in the output of any tool, you get a warning, and the model gets a masked copy. `hushhook leaks` shows the log: time, tool, rule and count. The log never holds the value itself.

## How it works

```text
the agent wants to run a tool
  |
  |-- before: file rules, command rules and size limits. Stop it, with a reason.
  |
  |-- during: Bash output goes through the mask, line by line.
  |
  '-- after:  every tool's output is scanned. You get a warning, the model gets
              a masked copy, and the log gets a line.
```

### Your permission settings stay as they are

hushhook does not approve anything on your behalf. Claude Code checks your permission rules against the command a hook returns, so rewriting a command in a mode that prompts would turn every allow-listed command into a prompt. That is why the default, `"wrap_bash": "auto"`, works like this:

- With permission checks turned off (bypass mode), Bash commands are rewritten so their output passes through the mask as it is produced.
- In every other mode, commands run exactly as written, and the output is masked straight after the tool finishes.

Either way the model gets the masked text. Set `"wrap_bash": "always"` to rewrite in every mode, or `"never"` to rely on the after-the-tool step alone.

## What it cannot stop

hushhook reduces accidents. It does not guarantee anything, and it is worth knowing where the edges are.

- **It only knows the formats in its rules.** A plain password, or an internal token with no recognizable shape, looks like any other text.
- **It reads common shell commands, not all of them.** A script that opens a file and prints it, `python -c`, or copying a file before reading it all get past the file rules. The mask still catches any known format in the output.
- **It is a seatbelt, not a sandbox.** The agent can still run code, reach the network and change files. An agent set on getting around a rule can do so. Use a real sandbox if that is your concern.
- **Command rules match text.** They catch the usual forms of a dangerous command, not every way to write it.
- **It only sees tool calls.** Anything you paste into the chat, or that the agent writes itself, goes straight through.
- **Masking happens after a command has run.** The secret was still used. If hushhook warns you about a real one, rotate it.
- **Replacing output needs a recent Claude Code.** On a version without output replacement you still get the warning and the log line, but the original output reaches the model. Bypass mode is the exception for Bash, since the mask runs inside the command.
- **If hushhook fails, your agent keeps working.** Any error in a hook means no protection for that call, by design, so a bug here never stops your session. Run `hushhook doctor` if something seems off.
- **Two side effects of rewriting Bash commands.** Only a `cd` at the start of a command carries over to the next one. A command that leaves a background process attached to its output waits for that process to finish, so send such output to a file. Commands ending in `&`, or using `nohup` or `setsid`, are left alone, and the after-the-tool step still covers them.

Linux and macOS are supported. Windows is untested so far.

## Configuration

All settings are optional. They live in `~/.config/hushhook/config.json`:

```json
{
  "max_read_lines": 300,
  "disabled": ["jwt"],
  "extra_rule_dirs": ["~/my-hushhook-rules"],
  "wrap_bash": "auto"
}
```

| Setting | What it does | Default |
| --- | --- | --- |
| `max_read_lines` | Reading or printing a longer file needs a range or a filter | `300` |
| `disabled` | Rule ids to turn off. `hushhook rules` lists them all | none |
| `extra_rule_dirs` | Your own rule folders, laid out as `<folder>/<kind>/<name>.rules` | none |
| `wrap_bash` | `auto`, `always` or `never`. See above | `auto` |

## Reading code with less

These work for Python and shell. Function bodies stay out of `map`, and `peek` drops comments and shows strings as `"..."` until you ask for them.

```text
$ hushhook map hushhook/hook.py
hushhook/hook.py  44 lines
imports: sys
def L9-23 respond(argv, raw)
def L26-40 main(argv)  -> respond

$ hushhook peek hushhook/hook.py main      # one function, or a range like 10:40
$ hushhook refs . respond                  # where a name is used, without the lines
$ hushhook doc hushhook/hook.py            # docstrings only
```

## Add a rule

A rule is a short paragraph in a text file, with no YAML or JSON to get right:

```text
id: github-classic-token
pattern: \bghp_[A-Za-z0-9]{36}\b
matches: ghp_{a*36}
ignores: ghp_short
```

If a token format, a file or a command is missing, adding it takes about five minutes, and it protects everyone who uses hushhook. [CONTRIBUTING.md](CONTRIBUTING.md) walks you through it.

## License

[MIT](LICENSE)
