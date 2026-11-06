"""Rule packs: plain text, one rule per paragraph, nothing to escape.

    id: github-classic-token
    pattern: ghp_[A-Za-z0-9]{36}
    matches: ghp_{a*36}
    ignores: ghp_short

Packs live in rules/<kind>/<ecosystem>.rules, where kind is secrets, files or
commands. Examples use {a*36} ("a" repeated 36 times), so the repository never
holds a string that looks like a real token.
"""

import fnmatch
import os
import re

KINDS = ("secrets", "files", "commands")
BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
MARKER = "[hushhook:%s]"

_FIELDS = {
    "secrets": {"id", "pattern", "body", "matches", "ignores"},
    "files": {"id", "glob", "except", "matches", "ignores"},
    "commands": {"id", "pattern", "reason", "matches", "ignores"},
}
_REQUIRED = {
    "secrets": ("id", "pattern", "matches"),
    "files": ("id", "glob", "matches"),
    "commands": ("id", "pattern", "reason", "matches"),
}
_REPEATABLE = {"glob", "except", "matches", "ignores"}
_FIELD = re.compile(r"^([a-z]+):[ \t]*(.*)$")
_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_REPEAT = re.compile(r"\{([^{}*]+)\*([0-9]+)\}")
_FLAGS = re.compile(r"^\(\?([a-zA-Z]+)\)")
_COUNT = re.compile(r"\{[0-9]*,?[0-9]*\}")


def _skip_class(pattern, index):
    """Return the index just past the character class starting at index."""
    end = index + 1
    if pattern[end : end + 1] == "^":
        end += 1
    if pattern[end : end + 1] == "]":
        end += 1
    while end < len(pattern) and pattern[end] != "]":
        end += 2 if pattern[end] == "\\" else 1
    return end + 1


def _skip_group(pattern, index):
    """Return the index just past the group starting at index."""
    depth = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            index = _skip_class(pattern, index)
            continue
        depth += (char == "(") - (char == ")")
        index += 1
        if depth == 0:
            break
    return index


def required_text(pattern):
    """Return (text, folded): text every match must contain, or ("", False) when unsure.

    Looking for that text first keeps the mask fast: most lines skip most rules
    without running a regular expression at all. folded means compare in lowercase.
    """
    flags = _FLAGS.match(pattern)
    if flags and set(flags.group(1)) - set("im"):
        return "", False
    folded = bool(flags) and "i" in flags.group(1)
    index = flags.end() if flags else 0
    best = run = ""
    while index < len(pattern):
        char = pattern[index]
        piece = ""
        if char == "|" or char == ")":
            return "", False
        if char == "\\":
            after = pattern[index + 1 : index + 2]
            if after in "xuUN" or after.isdigit():
                return "", False  # the characters that follow are a code, not text
            piece = after if not after.isalnum() else ""
            index += 2
        elif char == "[":
            index = _skip_class(pattern, index)
        elif char == "(":
            index = _skip_group(pattern, index)
        elif char == "{":
            counted = _COUNT.match(pattern, index)
            if not counted:
                return "", False
            index = counted.end()
        elif char in ".^$?*+":
            index += 1
        else:
            piece = char
            index += 1
        following = pattern[index : index + 1]
        if piece and following not in ("?", "*", "{"):
            run += piece
            if following != "+":
                continue
        best = max(best, run, key=len)
        run = ""
    best = max(best, run, key=len)
    if len(best) < 2:
        return "", False
    return (best.lower(), True) if folded else (best, False)


def expand(example):
    """Turn the {a*36} shorthand into the real text. Only tests and checks need this."""
    return _REPEAT.sub(lambda match: match.group(1) * int(match.group(2)), example)


class Rule:
    """One rule from a pack."""

    def __init__(self, kind, fields, source, line):
        self.kind = kind
        self.source = source
        self.line = line
        self.id = fields["id"][0]
        self.matches = fields.get("matches", [])
        self.ignores = fields.get("ignores", [])
        self.globs = fields.get("glob", [])
        self.excepts = fields.get("except", [])
        self.reason = fields.get("reason", [""])[0]
        self.regex = re.compile(fields["pattern"][0]) if "pattern" in fields else None
        self.body = re.compile(fields["body"][0]) if "body" in fields else None
        self._partial = self.regex is not None and "secret" in self.regex.groupindex
        self.hint, self.folded = required_text(fields["pattern"][0]) if "pattern" in fields else ("", False)

    def worth_trying(self, text, lowered):
        """False when this rule cannot match, which saves running the regular expression."""
        return not self.hint or self.hint in (lowered if self.folded else text)

    def hits(self, text):
        """True when this rule applies to text (a path for files rules)."""
        if self.kind == "files":
            return path_matches(self, text)
        return self.regex.search(text) is not None

    def mask(self, text):
        """Replace the secret. A (?P<secret>...) group keeps the words around it readable."""
        marker = MARKER % self.id
        if not self._partial:
            return self.regex.sub(lambda match: marker, text)

        def swap(match):
            start, end = match.span("secret")
            whole = match.group(0)
            return whole[: start - match.start()] + marker + whole[end - match.start() :]

        return self.regex.sub(swap, text)


class RuleSet:
    """Loaded rules by kind, plus anything that could not be loaded."""

    def __init__(self):
        self.secrets = []
        self.files = []
        self.commands = []
        self.errors = []

    def all(self):
        return self.secrets + self.files + self.commands


def _part_hit(part, glob):
    if fnmatch.fnmatchcase(part, glob):
        return True
    # A shell argument may itself hold a wildcard: `cat .en*` should still hit `.env`.
    return any(char in part for char in "*?[") and fnmatch.fnmatchcase(glob, part)


def _glob_hit(glob, parts):
    wanted = glob.split("/")
    if len(wanted) > len(parts):
        return False
    return all(_part_hit(part, item) for part, item in zip(parts[-len(wanted) :], wanted))


def path_matches(rule, path):
    """Match a path by its name, or by its last folders when the glob has a slash."""
    parts = [part for part in str(path).replace("\\", "/").split("/") if part not in ("", ".")]
    if not parts:
        return False
    if any(_glob_hit(glob, parts) for glob in rule.excepts):
        return False
    return any(_glob_hit(glob, parts) for glob in rule.globs)


def _build(block, kind, source, errors):
    fields = {}
    where = "%s:%d" % (source, block[0][0])
    for number, line in block:
        found = _FIELD.match(line)
        if not found or found.group(1) not in _FIELDS[kind]:
            errors.append(
                "%s:%d: expected one of %s, got: %s"
                % (source, number, ", ".join(sorted(_FIELDS[kind])), line.split(":")[0][:40])
            )
            return None
        key, value = found.group(1), found.group(2).strip()
        if key in fields and key not in _REPEATABLE:
            errors.append("%s:%d: %s appears twice" % (source, number, key))
            return None
        fields.setdefault(key, []).append(value)
    missing = [key for key in _REQUIRED[kind] if not fields.get(key)]
    if missing:
        errors.append("%s: missing %s" % (where, ", ".join(missing)))
        return None
    if not _ID.match(fields["id"][0]):
        errors.append("%s: id must be lowercase words joined by hyphens" % where)
        return None
    try:
        return Rule(kind, fields, source, block[0][0])
    except re.error as exc:
        errors.append("%s: %s has a bad regular expression: %s" % (where, fields["id"][0], exc))
        return None


def parse_text(text, kind, source="<text>"):
    """Parse one pack. Returns (rules, errors); a bad rule never stops the good ones."""
    rules, errors, block = [], [], []

    def flush():
        if block:
            rule = _build(block, kind, source, errors)
            if rule is not None:
                rules.append(rule)
            del block[:]

    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            flush()
        elif not line.startswith("#"):
            block.append((number, line))
    flush()
    return rules, errors


def load_rules(config=None, kinds=KINDS, include_disabled=False):
    """Load the built-in packs, then extra_rule_dirs. A later rule with the same id wins."""
    config = config or {}
    disabled = set(config.get("disabled") or ())
    extra = [os.path.expanduser(folder) for folder in config.get("extra_rule_dirs") or ()]
    merged = {}
    result = RuleSet()
    for position, directory in enumerate([BUILTIN_DIR] + extra):
        for kind in kinds:
            folder = os.path.join(directory, kind)
            try:
                names = sorted(os.listdir(folder))
            except OSError:
                continue
            for name in names:
                if not name.endswith(".rules"):
                    continue
                path = os.path.join(folder, name)
                try:
                    with open(path, encoding="utf-8") as handle:
                        text = handle.read()
                except (OSError, UnicodeDecodeError) as exc:
                    result.errors.append("%s: %s" % (path, exc))
                    continue
                rules, errors = parse_text(text, kind, path)
                result.errors.extend(errors)
                for rule in rules:
                    if position == 0 and (kind, rule.id) in merged:
                        result.errors.append("%s: duplicate id %s" % (path, rule.id))
                    merged[(kind, rule.id)] = rule
    for (kind, rule_id), rule in merged.items():
        if include_disabled or rule_id not in disabled:
            getattr(result, kind).append(rule)
    return result


def check_rule(rule):
    """Run a rule's examples. Messages show the {a*36} form, never the expanded text."""
    problems = []
    for example in rule.matches:
        if not rule.hits(expand(example)):
            problems.append("should match but does not: %s" % example)
    for example in rule.ignores:
        if rule.hits(expand(example)):
            problems.append("should not match but does: %s" % example)
    return problems
