"""The decisions, with no knowledge of any particular agent.

Adapters translate each agent's hook format to these calls and back.
"""

import os
import re
import shlex
import sys

from . import shell
from .config import load_config
from .tools import deny_hint
from .rules import load_rules, path_matches

BIG_RANGE = 200

_WHOLE_FILE = {"cat", "tac", "nl", "less", "more", "most", "bat", "batcat"}
_SCRIPT_FIRST = {"grep", "egrep", "fgrep", "rg", "ag", "sed", "awk", "gawk", "jq", "yq"}
_READERS = (
    _WHOLE_FILE
    | _SCRIPT_FIRST
    | {"head", "tail", "strings", "xxd", "hexdump", "od", "base64", "cut", "sort", "uniq", "paste", "column"}
)
_PASS_THROUGH = _WHOLE_FILE | {"tee"}
_NATIVE_VIEW = (".ipynb",)
_SED_RANGE = re.compile(r"([0-9]+)\s*,\s*([0-9]+|\$)\s*p")
_SED_QUIET = re.compile(r"^(?:-[a-zA-Z]*n[a-zA-Z]*|--quiet|--silent)$")


class Verdict:
    """allow, deny with a reason, or rewrite to a new command."""

    def __init__(self, action, reason="", command=None):
        self.action = action
        self.reason = reason
        self.command = command


ALLOW = Verdict("allow")


def deny(reason):
    return Verdict("deny", reason)


class Context:
    """Settings and rules for one check."""

    def __init__(self, config=None, kinds=("files", "commands")):
        self.config = load_config() if config is None else config
        self.rules = load_rules(self.config, kinds=kinds)
        self.max_read_lines = self.config.get("max_read_lines", 300)

    def file_rule(self, path):
        """Return the files rule that covers path, following symlinks."""
        names = [path]
        try:
            real = os.path.realpath(os.path.expanduser(path))
            if real != path:
                names.append(real)
        except (OSError, ValueError):
            pass
        for rule in self.rules.files:
            if any(path_matches(rule, name) for name in names):
                return rule
        return None


def mask_command():
    """The shell text that runs the mask, built to work without hushhook on PATH."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return "PYTHONPATH=%s %s -m hushhook.mask" % (shlex.quote(root), shlex.quote(sys.executable or "python3"))


def count_lines(path, cap):
    """Count lines, stopping at cap. Anything but a readable regular file counts as 0."""
    try:
        if not os.path.isfile(path):
            return 0
        count = 0
        last = b""
        with open(path, "rb") as handle:
            for _ in range(1024):
                chunk = handle.read(1 << 16)
                if not chunk:
                    break
                count += chunk.count(b"\n")
                last = chunk
                if count >= cap:
                    return count
        return count + 1 if last and not last.endswith(b"\n") else count
    except OSError:
        return 0


def _is_text(path):
    if path.lower().endswith(_NATIVE_VIEW) or not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as handle:
            return b"\0" not in handle.read(8192)
    except OSError:
        return False


def _secret_file_reason(path, rule):
    return (
        "hushhook blocked reading %s (rule %s): this file usually holds secrets. "
        "Ask the user for the specific value you need." % (path, rule.id)
        + deny_hint(rule.id)
    )


def _big_file_reason(path, limit):
    return (
        "hushhook stopped a big dump: %s has more than %d lines. Narrow it first: "
        "read a range, search with grep, or run `hushhook map %s` for an outline of a "
        "Python or shell file." % (path, limit, path)
    )


def check_read(path, limit, ctx):
    """Decide on reading a file. limit is the number of lines asked for, or None."""
    if not path:
        return ALLOW
    rule = ctx.file_rule(path)
    if rule is not None:
        return deny(_secret_file_reason(path, rule))
    if isinstance(limit, int) and 0 < limit <= ctx.max_read_lines:
        return ALLOW
    full = os.path.expanduser(path)
    if _is_text(full) and count_lines(full, ctx.max_read_lines + 1) > ctx.max_read_lines:
        return deny(_big_file_reason(path, ctx.max_read_lines))
    return ALLOW


def _file_args(verb, args):
    names = [arg for arg in args if arg and not arg.startswith("-")]
    if verb in ("head", "tail"):
        names = [name for name in names if not name.lstrip("+").isdigit()]
    return names[1:] if verb in _SCRIPT_FIRST else names


def _line_request(args):
    """Read -n from head or tail. Returns (plus, count), or None for the default."""
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        value = None
        if arg in ("-n", "--lines"):
            value = args[index] if index < len(args) else ""
            index += 1
        elif arg.startswith("--lines="):
            value = arg.split("=", 1)[1]
        elif arg.startswith("-n"):
            value = arg[2:]
        elif re.fullmatch(r"-[0-9]+", arg):
            value = arg[1:]
        found = re.fullmatch(r"(\+?)([0-9]+)", value) if value else None
        if found:
            return found.group(1) == "+", int(found.group(2))
    return None


def _asks_too_much(wanted, path):
    """True when more than BIG_RANGE lines are asked for, unless the file proves smaller."""
    if wanted <= BIG_RANGE:
        return False
    total = count_lines(path, BIG_RANGE + 1)
    return total == 0 or total > BIG_RANGE


def _rest_is_big(start, path):
    """True when the file runs on for more than BIG_RANGE lines after line start."""
    return count_lines(path, start + BIG_RANGE + 1) - start + 1 > BIG_RANGE


def _too_much_of(verb, args, path):
    if verb in ("head", "tail"):
        request = _line_request(args)
        if request is None:
            return False
        plus, count = request
        return _rest_is_big(count, path) if plus and verb == "tail" else _asks_too_much(count, path)
    if verb == "sed" and any(_SED_QUIET.match(arg) for arg in args):
        for found in _SED_RANGE.finditer(" ".join(args)):
            start, end = int(found.group(1)), found.group(2)
            if _rest_is_big(start, path) if end == "$" else _asks_too_much(int(end) - start + 1, path):
                return True
    return False


def _big_dump(pipeline, base, limit):
    """Return the reason to stop a pipeline that prints a large file unfiltered."""
    verb, args = pipeline[0].command()
    if verb is None or pipeline[-1].stdout_to_file:
        return None
    for segment in pipeline[1:]:
        following = segment.command()[0]
        if following is not None and following not in _PASS_THROUGH:
            return None
    for name in _file_args(verb, args) + pipeline[0].reads:
        path = os.path.join(base, os.path.expanduser(name))
        if verb in _WHOLE_FILE:
            if count_lines(path, limit + 1) > limit:
                return _big_file_reason(name, limit)
        elif _too_much_of(verb, args, path):
            return (
                "hushhook stopped a big dump: that asks for more than %d lines of %s. "
                "Read a smaller range or filter it with grep." % (BIG_RANGE, name)
            )
    return None


def check_shell(command, cwd, ctx):
    """Decide on a shell command: deny it, or rewrite it to run through the mask."""
    text = (command or "").strip()
    if not text:
        return ALLOW
    for rule in ctx.rules.commands:
        if rule.regex.search(text):
            return deny(
                "hushhook blocked this command (rule %s): %s "
                "If it is really intended, ask the user to run it." % (rule.id, rule.reason)
                + deny_hint(rule.id)
            )
    base = cwd or os.getcwd()
    for folder in shell.leading_dirs(text):
        base = os.path.normpath(os.path.join(base, os.path.expanduser(folder)))
    for pipeline in shell.pipelines(text):
        for segment in pipeline:
            verb, args = segment.command()
            if verb not in _READERS:
                continue
            for name in _file_args(verb, args) + segment.reads:
                rule = ctx.file_rule(name)
                if rule is not None:
                    return deny(_secret_file_reason(name, rule))
        reason = _big_dump(pipeline, base, ctx.max_read_lines)
        if reason:
            return deny(reason)
    rewritten = shell.wrap(text, mask_command())
    return Verdict("rewrite", command=rewritten) if rewritten else ALLOW
