"""Just enough shell reading for hushhook's checks.

This is not a shell parser. It follows the one-liners agents usually write and
gives up quietly on anything stranger: a command it cannot follow is not gated,
and the output mask still applies.
"""

import os
import re
import shlex

PUNCTUATION = ";&|()<>\n"
_PUNCTUATION_SET = set(PUNCTUATION)

_HEREDOC = re.compile(
    r"(?<!<)<<(?!<)-?[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1([^\n]*)\n(?:.*?\n)??[ \t]*\2[ \t]*(?:\n|\Z)",
    re.S,
)
_CD = re.compile(r"""cd(?:[ \t]+("[^"\n]*"|'[^'\n]*'|[^\s;&|"'()]+))?[ \t]*(?:&&\s*|;\s*|\n\s*|$)""")
_LONE_AMPERSAND = re.compile(r"(?<![&<>|])&(?![&>])")
_DETACH = re.compile(r"(?:^|[;&|(\n]\s*)(?:nohup|setsid|disown)\b")
_MASKED = re.compile(r"\|&?[^|\n]*\bhushhook(?:\s+|\.)mask\b")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPERS = {
    "sudo", "command", "builtin", "exec", "time", "nice", "ionice", "env",
    "then", "do", "else", "elif", "if", "while", "until", "!", "{",
}


def strip_heredocs(command):
    """Drop here-document bodies: they are data, not commands."""
    return _HEREDOC.sub(lambda match: match.group(3) + "\n", command)


def blank_quotes(text):
    """Hide quoted and escaped text behind underscores, keeping every position."""
    out = []
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and quote != "'" and index + 1 < len(text):
            out.append("__")
            index += 2
            continue
        if quote:
            if char == quote:
                quote = None
                out.append(char)
            else:
                out.append("\n" if char == "\n" else "_")
        else:
            if char in "'\"":
                quote = char
            out.append(char)
        index += 1
    return "".join(out)


def is_backgrounded(command):
    """True for `&`, nohup, setsid and disown. A pipe would keep waiting for those."""
    code = blank_quotes(strip_heredocs(command))
    return bool(_LONE_AMPERSAND.search(code) or _DETACH.search(code))


def is_masked(command):
    """True when the command already pipes into hushhook mask."""
    return bool(_MASKED.search(blank_quotes(command)))


def _peel(command):
    rest = command.strip()
    prefix = ""
    targets = []
    while rest:
        found = _CD.match(rest)
        if not found:
            break
        prefix += found.group(0)
        rest = rest[found.end() :]
        if found.group(1):
            targets.append(found.group(1).strip("\"'"))
    return prefix, rest, targets


def peel_cd(command):
    """Split leading cd steps from the rest. Returns (prefix, rest)."""
    return _peel(command)[:2]


def leading_dirs(command):
    """Return the folders named by leading cd steps."""
    return _peel(command)[2]


def wrap(command, mask_command):
    """Send a command's output through the mask, or return None to leave it alone.

    The leading cd stays outside so the working directory carries to the next
    call. The && means a failed cd still stops everything after it. pipefail is
    on for our own pipe, which passes the command's exit code through, and off
    again inside the group, so the command's own pipelines behave as written.
    """
    text = (command or "").strip()
    if not text or is_masked(text) or is_backgrounded(text):
        return None
    prefix, rest = peel_cd(text)
    if not rest:
        return None
    return "%sset -o pipefail && {\nset +o pipefail\n%s\n} 2>&1 | %s" % (prefix, rest, mask_command)


class Segment:
    """One simple command inside a pipeline."""

    def __init__(self):
        self.words = []
        self.reads = []
        self.stdout_to_file = False

    def command(self):
        """Return (verb, args), skipping env assignments and wrappers such as sudo."""
        index = 0
        while index < len(self.words):
            word = self.words[index]
            if word in _WRAPPERS or _ASSIGNMENT.match(word) or (index and word.startswith("-")):
                index += 1
                continue
            return os.path.basename(word), self.words[index + 1 :]
        return None, []


def _words(text):
    lexer = shlex.shlex(text, posix=True, punctuation_chars=PUNCTUATION)
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def pipelines(command):
    """Return a command line as a list of pipelines, each a list of Segments."""
    try:
        words = _words(strip_heredocs(command or ""))
    except ValueError:
        return []
    result, pipeline, segment = [], [], Segment()
    index = 0
    while index < len(words):
        word = words[index]
        index += 1
        if not word or set(word) - _PUNCTUATION_SET:
            segment.words.append(word)
        elif "(" in word or ")" in word or not set(word) & set("<>"):
            if segment.words:
                pipeline.append(segment)
            segment = Segment()
            if word.strip("\n") not in ("|", "|&"):
                if pipeline:
                    result.append(pipeline)
                pipeline = []
        else:
            target = words[index] if index < len(words) else ""
            index += 1
            handle = segment.words.pop() if segment.words and segment.words[-1].isdigit() else ""
            if word == "<":
                segment.reads.append(target)
            elif "<" in word or (word.endswith("&") and target.isdigit()):
                pass
            elif handle != "2":
                segment.stdout_to_file = True
    if segment.words:
        pipeline.append(segment)
    if pipeline:
        result.append(pipeline)
    return result
