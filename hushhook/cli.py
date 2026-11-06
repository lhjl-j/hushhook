"""Command line: hushhook <command>."""

import argparse
import json
import os
import shlex
import shutil
import sys
import tempfile
import time

from . import __version__, codemap, mask, scan
from .config import check_config, config_path, load_config, state_dir
from .rules import KINDS, check_rule, expand, load_rules, path_matches

HOOK_MODULE = "hushhook.hook"
HOOK_TIMEOUT = 10
EVENTS = (("PreToolUse", "Read|Bash", "pre"), ("PostToolUse", "*", "post"))


def settings_path(project=False):
    if project:
        return os.path.join(os.getcwd(), ".claude", "settings.json")
    base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    return os.path.join(base, "settings.json")


def hook_command(event):
    """The command for settings.json, built to work without hushhook on PATH."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return "PYTHONPATH=%s %s -m %s %s" % (shlex.quote(root), shlex.quote(sys.executable), HOOK_MODULE, event)


def _is_ours(entry):
    return isinstance(entry, dict) and HOOK_MODULE in str(entry.get("command", ""))


def _load_settings(path):
    """Return the parsed settings, or raise ValueError if they cannot be merged safely."""
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("hooks", {}), dict):
        raise ValueError("expected a JSON object with a hooks object")
    for groups in data.get("hooks", {}).values():
        if not isinstance(groups, list):
            raise ValueError("expected each hook event to hold a list")
    return data


def add_hooks(settings):
    """Add our hooks, or refresh their paths. Returns True when something changed."""
    changed = False
    hooks = settings.setdefault("hooks", {})
    for event, matcher, argument in EVENTS:
        wanted = hook_command(argument)
        groups = hooks.setdefault(event, [])
        found = False
        for group in groups:
            for entry in group.get("hooks", []) if isinstance(group, dict) else []:
                if _is_ours(entry):
                    found = True
                    if entry.get("command") != wanted:
                        entry["command"] = wanted
                        changed = True
        if not found:
            groups.append(
                {"matcher": matcher, "hooks": [{"type": "command", "command": wanted, "timeout": HOOK_TIMEOUT}]}
            )
            changed = True
    return changed


def remove_hooks(settings):
    """Take out only what we added. Returns True when something changed."""
    changed = False
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False
    for event in list(hooks):
        kept = []
        for group in hooks[event]:
            entries = group.get("hooks", []) if isinstance(group, dict) else []
            others = [entry for entry in entries if not _is_ours(entry)]
            if len(others) == len(entries):
                kept.append(group)
                continue
            changed = True
            if others:
                group["hooks"] = others
                kept.append(group)
        hooks[event] = kept
        if changed and not kept:
            del hooks[event]
    if changed and not hooks:
        del settings["hooks"]
    return changed


def _backup(path):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = "%s.hushhook-backup-%s" % (path, stamp)
    number = 1
    while os.path.exists(target):
        number += 1
        target = "%s.hushhook-backup-%s-%d" % (path, stamp, number)
    shutil.copy2(path, target)
    return target


def _save(path, data):
    real = os.path.realpath(path)
    folder = os.path.dirname(real)
    os.makedirs(folder, exist_ok=True)
    mode = os.stat(real).st_mode & 0o7777 if os.path.exists(real) else 0o644
    handle, temp = tempfile.mkstemp(dir=folder, prefix=".settings-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.chmod(temp, mode)
        os.replace(temp, real)
    except BaseException:
        if os.path.exists(temp):
            os.unlink(temp)
        raise


def _update_settings(project, change, done, unchanged):
    path = settings_path(project)
    try:
        settings = _load_settings(path)
    except (OSError, ValueError) as exc:
        print("hushhook: left %s untouched, it could not be read: %s" % (path, exc), file=sys.stderr)
        return 1
    if not change(settings):
        print(unchanged % path)
        return 0
    backup = _backup(path) if os.path.exists(path) else None
    _save(path, settings)
    print(done % path)
    if backup:
        print("Backup: %s" % backup)
    return 0


def cmd_install(args):
    result = _update_settings(
        args.project, add_hooks, "Installed into %s", "Already installed in %s, nothing changed."
    )
    if result == 0:
        print("Start a new Claude Code session to pick it up, then run: hushhook doctor")
    return result


def cmd_uninstall(args):
    return _update_settings(
        args.project, remove_hooks, "Removed from %s", "Nothing to remove from %s."
    )


def _rule_problems(rules):
    return [
        "%s:%d %s: %s" % (rule.source, rule.line, rule.id, problem)
        for rule in rules.all()
        for problem in check_rule(rule)
    ]


def cmd_rules(args):
    config = load_config()
    rules = load_rules(config, include_disabled=True)
    if args.action == "test":
        problems = rules.errors + _rule_problems(rules)
        for problem in problems:
            print("FAIL " + problem)
        counts = ", ".join("%d %s" % (len(getattr(rules, kind)), kind) for kind in KINDS)
        print("%s: %s" % ("failed" if problems else "all examples pass", counts))
        return 1 if problems else 0
    disabled = set(config["disabled"])
    for kind in KINDS:
        for rule in getattr(rules, kind):
            state = "  (disabled)" if rule.id in disabled else ""
            print("%-9s %-34s %s%s" % (kind, rule.id, os.path.basename(rule.source), state))
    for error in rules.errors:
        print("FAIL " + error)
    return 1 if rules.errors else 0


def _hooks_present(path):
    try:
        settings = _load_settings(path)
    except (OSError, ValueError):
        return False
    found = set()
    for event, groups in settings.get("hooks", {}).items():
        for group in groups:
            for entry in group.get("hooks", []) if isinstance(group, dict) else []:
                if _is_ours(entry):
                    found.add(event)
    return all(event in found for event, _, _ in EVENTS)


def cmd_doctor(_args):
    failures = []

    def report(passed, text):
        print("%s %s" % ("ok  " if passed else "FAIL", text))
        if not passed:
            failures.append(text)

    report(sys.version_info >= (3, 9), "Python %d.%d" % sys.version_info[:2])
    problems = check_config()
    report(not problems, "config %s%s" % (config_path(), ": " + "; ".join(problems) if problems else ""))
    config = load_config()
    rules = load_rules(config)
    report(
        not rules.errors,
        "rules: %s" % ", ".join("%d %s" % (len(getattr(rules, kind)), kind) for kind in KINDS),
    )
    for error in rules.errors:
        print("     " + error)
    broken = _rule_problems(rules)
    report(not broken, "rule examples: %d failing" % len(broken))

    sample = next((rule for rule in rules.secrets if rule.body is None), None)
    if sample is not None:
        text = expand(sample.matches[0])
        report(text not in mask.mask_text(text + "\n", rules.secrets), "mask hides a known secret format")

    folder = state_dir()
    try:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        report(os.access(folder, os.W_OK), "leak log folder %s" % folder)
    except OSError:
        report(False, "leak log folder %s" % folder)

    for label, path in (("user", settings_path()), ("project", settings_path(True))):
        state = "installed" if _hooks_present(path) else "not installed"
        print("info %s settings %s: %s" % (label, path, state))
    print("info installed as a Claude Code plugin? Check /plugin; settings will not show it.")
    return 1 if failures else 0


def _blocked_file(path):
    """Keep the code tools from reading what the Read gate would refuse."""
    for rule in load_rules(load_config(), kinds=("files",)).files:
        if path_matches(rule, path):
            print("hushhook: not reading %s (rule %s): it usually holds secrets." % (path, rule.id), file=sys.stderr)
            return True
    return False


def _print_code(path, produce):
    if _blocked_file(path):
        return 1
    if not os.path.isfile(path):
        print("hushhook: no such file: %s" % path, file=sys.stderr)
        return 1
    if codemap.language(path) is None:
        print("hushhook: %s is not Python or shell yet." % path, file=sys.stderr)
        return 1
    try:
        lines = produce()
    except SyntaxError as exc:
        print("hushhook: %s does not parse: %s" % (path, exc), file=sys.stderr)
        return 1
    if not lines:
        print("hushhook: nothing found.", file=sys.stderr)
        return 1
    print("\n".join(lines))
    return 0


def cmd_map(args):
    return _print_code(args.file, lambda: codemap.outline(args.file, args.filter))


def cmd_peek(args):
    return _print_code(
        args.file, lambda: codemap.peek(args.file, args.target, args.keep_strings, args.raw)
    )


def cmd_refs(args):
    lines = codemap.references(args.path, args.name)
    if lines:
        print("\n".join(lines))
    return 0 if lines else 1


def cmd_doc(args):
    return _print_code(args.file, lambda: codemap.docs(args.file, args.name))


def cmd_mask(_args):
    return mask.main()


def cmd_leaks(_args):
    path = scan.leaks_path()
    if not os.path.exists(path):
        print("No possible secrets recorded.")
        return 0
    with open(path, encoding="utf-8") as handle:
        sys.stdout.write(handle.read())
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="hushhook",
        description="Keeps secrets and big dumps out of your AI coding agent's conversation.",
    )
    parser.add_argument("--version", action="version", version="hushhook " + __version__)
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    sub = commands.add_parser("install", help="add the hooks to Claude Code settings")
    sub.add_argument("--project", action="store_true", help="use ./.claude/settings.json")
    sub.set_defaults(run=cmd_install)

    sub = commands.add_parser("uninstall", help="remove the hooks from Claude Code settings")
    sub.add_argument("--project", action="store_true", help="use ./.claude/settings.json")
    sub.set_defaults(run=cmd_uninstall)

    sub = commands.add_parser("doctor", help="check that everything works")
    sub.set_defaults(run=cmd_doctor)

    sub = commands.add_parser("rules", help="list the rules, or `rules test` to run their examples")
    sub.add_argument("action", nargs="?", choices=["test"])
    sub.set_defaults(run=cmd_rules)

    sub = commands.add_parser("mask", help="mask secrets from stdin to stdout")
    sub.set_defaults(run=cmd_mask)

    sub = commands.add_parser("leaks", help="show the log of possible secrets (ids and counts only)")
    sub.set_defaults(run=cmd_leaks)

    sub = commands.add_parser("map", help="outline a file without its function bodies")
    sub.add_argument("file")
    sub.add_argument("filter", nargs="?", help="only names containing this text")
    sub.set_defaults(run=cmd_map)

    sub = commands.add_parser("peek", help="show one function, class or start:end range")
    sub.add_argument("file")
    sub.add_argument("target", help="a name, or a line range like 10:40")
    sub.add_argument("--keep-strings", action="store_true", help="show string contents")
    sub.add_argument("--raw", action="store_true", help="show the lines exactly as written")
    sub.set_defaults(run=cmd_peek)

    sub = commands.add_parser("refs", help="list where a name is used, without the lines")
    sub.add_argument("path")
    sub.add_argument("name")
    sub.set_defaults(run=cmd_refs)

    sub = commands.add_parser("doc", help="show docstrings or function comments")
    sub.add_argument("file")
    sub.add_argument("name", nargs="?")
    sub.set_defaults(run=cmd_doc)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "run", None):
        parser.print_help()
        return 0
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
