"""Helpers for the moments people hit most: a wrong block, and a rule of their own.

`hushhook explain <rule-id>` says where a rule lives, how to turn it off and how
to report a wrong match. `hushhook rules new` and `rules share` make a rule for
your own service and pass it on. Links only ever carry a rule id or a rule file,
never a command or any text that was blocked.
"""

import difflib
import json
import os
import re
import sys
from urllib.parse import quote

from . import __version__
from .config import config_path, load_config
from .rules import _ID, BUILTIN_DIR, KINDS, check_rule, expand, load_rules, parse_text

REPO = "https://github.com/monarchsofchaos004-gif/hushhook"

TEMPLATES = {
    "secrets": (
        "# Mask a token or key format for your own service.\n"
        "# Remove the leading '# ' from the lines below and fill them in.\n"
        "# {a*36} stands for 'a' repeated 36 times, so no real token is ever stored here.\n"
        "#\n"
        "# id: {id}\n"
        "# pattern: \\bacme_[A-Za-z0-9]{36}\\b\n"
        "# matches: acme_{a*36}\n"
        "# ignores: acme_short\n"
    ),
    "files": (
        "# Stop reads of a file that holds secrets in your own tooling.\n"
        "# Remove the leading '# ' from the lines below and fill them in.\n"
        "#\n"
        "# id: {id}\n"
        "# glob: .acme/credentials\n"
        "# matches: .acme/credentials\n"
        "# matches: home/user/.acme/credentials\n"
        "# ignores: .acme/README.md\n"
    ),
    "commands": (
        "# Stop a command that is hard to undo in your own tooling.\n"
        "# Remove the leading '# ' from the lines below and fill them in.\n"
        "#\n"
        "# id: {id}\n"
        "# pattern: \\bacme\\s+destroy\\b\n"
        "# reason: this deletes production data. Ask the user to run it.\n"
        "# matches: acme destroy --all\n"
        "# ignores: acme status\n"
    ),
}


def issue_link(rule_id):
    title = quote("Wrong match: " + rule_id, safe="")
    return "%s/issues/new?template=wrong_match.yml&title=%s" % (REPO, title)


def deny_hint(rule_id):
    return " If this looks wrong, the user can run: hushhook explain %s" % rule_id


def _where(rule):
    source = rule.source
    if source.startswith(BUILTIN_DIR + os.sep):
        source = "hushhook/rules/" + os.path.relpath(source, BUILTIN_DIR)
    return "%s:%d" % (source, rule.line)


def cmd_explain(rule_id):
    config = load_config()
    rules = load_rules(config, include_disabled=True)
    found = [rule for rule in rules.all() if rule.id == rule_id]
    if not found:
        close = difflib.get_close_matches(rule_id, sorted({r.id for r in rules.all()}), n=3, cutoff=0.0)
        print("No rule with the id %s." % rule_id, file=sys.stderr)
        if close:
            print("Closest ids: " + ", ".join(close), file=sys.stderr)
        return 1
    disabled = set(config.get("disabled") or ())
    for rule in found:
        print("Rule:     %s" % rule.id)
        print("Kind:     %s" % rule.kind)
        print("File:     %s" % _where(rule))
        if rule.kind == "files":
            print("Glob:     " + ", ".join(rule.globs))
            if rule.excepts:
                print("Except:   " + ", ".join(rule.excepts))
        else:
            print("Pattern:  %s" % rule.regex.pattern)
        if rule.reason:
            print("Reason:   %s" % rule.reason)
        print("Status:   %s" % ("turned off in your config" if rule.id in disabled else "on"))
        print()
    print("To turn it off, add the id to \"disabled\" in %s:" % config_path())
    print('  {"disabled": ["%s"]}' % rule_id)
    print()
    print("Think it matched by mistake? Tell us (only the rule id is sent):")
    print("  " + issue_link(rule_id))
    return 0


def rules_root():
    return os.path.join(os.path.dirname(config_path()), "rules")


def _same_dir(left, right):
    return os.path.realpath(os.path.expanduser(left)) == os.path.realpath(os.path.expanduser(right))


def _ensure_loaded(root):
    """Make sure extra_rule_dirs lists root. Returns True when the config was changed."""
    path = config_path()
    data = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("%s: expected a JSON object" % path)
    folders = data.get("extra_rule_dirs") or []
    if not isinstance(folders, list):
        raise ValueError("%s: extra_rule_dirs must be a list" % path)
    if any(isinstance(item, str) and _same_dir(item, root) for item in folders):
        return False
    data["extra_rule_dirs"] = folders + [root]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    os.replace(temporary, path)
    return True


def _check_names(kind, rule_id):
    if kind not in KINDS:
        print("Unknown kind %r. Use one of: %s." % (kind, ", ".join(KINDS)), file=sys.stderr)
        return False
    if not _ID.match(rule_id or ""):
        print("The id must be lowercase letters and digits joined by hyphens, like acme-token.", file=sys.stderr)
        return False
    return True


def cmd_new(kind, rule_id):
    if not _check_names(kind, rule_id):
        return 1
    builtin = load_rules({}, include_disabled=True)
    if any(rule.id == rule_id for rule in builtin.all()):
        print("A built-in rule already uses the id %s. Pick another id." % rule_id, file=sys.stderr)
        return 1
    root = rules_root()
    path = os.path.join(root, kind, rule_id + ".rules")
    if os.path.exists(path):
        print("Already there, left as it is: " + path)
        return 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(TEMPLATES[kind].replace("{id}", rule_id))
    try:
        changed = _ensure_loaded(root)
    except (OSError, ValueError) as exc:
        print("Created %s, but could not update the config: %s" % (path, exc), file=sys.stderr)
        print('Add "%s" to extra_rule_dirs yourself.' % root, file=sys.stderr)
        return 1
    print("Created " + path)
    if changed:
        print("Added %s to extra_rule_dirs in %s" % (root, config_path()))
    print("Edit the file, then run `hushhook rules test` to check your examples.")
    print("Others using this service would benefit too: `hushhook rules share %s` makes a link." % rule_id)
    return 0


def _find_file(rule_id):
    for kind in KINDS:
        path = os.path.join(rules_root(), kind, rule_id + ".rules")
        if os.path.isfile(path):
            return kind, path
    return None, None


def _token_like(text, secrets):
    """Names of secrets rules that match text, which would mean a real-looking token."""
    return sorted({rule.id for rule in secrets if rule.hits(text)})


def share_link(kind, rule_id, content):
    return "%s/new/main/hushhook/rules/%s?filename=%s.rules&value=%s" % (
        REPO,
        kind,
        quote(rule_id, safe=""),
        quote(content, safe=""),
    )


def cmd_share(rule_id):
    if not _ID.match(rule_id or ""):
        print("The id must be lowercase letters and digits joined by hyphens.", file=sys.stderr)
        return 1
    kind, path = _find_file(rule_id)
    if path is None:
        print("No file for %s in %s. Make one with `hushhook rules new`." % (rule_id, rules_root()), file=sys.stderr)
        return 1
    with open(path, encoding="utf-8") as handle:
        content = handle.read()
    rules, errors = parse_text(content, kind, path)
    mine = [rule for rule in rules if rule.id == rule_id]
    problems = list(errors)
    if not mine:
        problems.append("no rule with id %s in the file yet (are the lines still commented out?)" % rule_id)
    for rule in mine:
        problems.extend(check_rule(rule))
    if problems:
        print("Not ready to share yet:", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return 1
    secrets = load_rules({}, kinds=("secrets",), include_disabled=True).secrets
    texts = [content] + [expand(item) for rule in mine for item in rule.matches + rule.ignores]
    hit = sorted({name for text in texts for name in _token_like(text, secrets)})
    if hit:
        print(
            "Held back: the file has text that looks like a real secret (matches %s)." % ", ".join(hit),
            file=sys.stderr,
        )
        print("Write examples with the {a*36} form, like acme_{a*36}, then try again.", file=sys.stderr)
        return 1
    print("Your examples pass. Others using this service would benefit too.")
    print("Open this link to pass the rule on (hushhook %s):" % __version__)
    print(share_link(kind, rule_id, content))
    return 0
