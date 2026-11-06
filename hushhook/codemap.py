"""A cheap look at source code: the outline first, then only the lines you need.

Python is read with ast and shell functions with a small scanner. To add another
language, give LANGUAGES an entry and write its outline and quiet functions.
"""

import ast
import io
import os
import re
import tokenize

from .shell import blank_quotes

LANGUAGES = {".py": "python", ".sh": "shell", ".bash": "shell", ".zsh": "shell"}
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".venv", ".mypy_cache", ".pytest_cache",
    "__pycache__", "node_modules", "venv", "build", "dist",
}

_SH_DEF = (
    re.compile(r"^\s*(?:function\s+)?([A-Za-z_][\w:-]*)\s*\(\s*\)"),
    re.compile(r"^\s*function\s+([A-Za-z_][\w:-]*)\b"),
)
_STRING_START = re.compile(r"^([A-Za-z]*)('''|\"\"\"|'|\")")
_SH_STRING = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")
_SH_PLAIN_VAR = re.compile(r"^\"\$\{?\w+\}?\"$")


class Item:
    """A function or class: name, line range, argument names and local calls."""

    def __init__(self, name, start, end, args="", calls=(), depth=0, kind="def"):
        self.name = name
        self.start = start
        self.end = end
        self.args = args
        self.calls = calls
        self.depth = depth
        self.kind = kind


def language(path):
    """Return "python", "shell", or None for a file this module cannot read."""
    known = LANGUAGES.get(os.path.splitext(path)[1].lower())
    if known:
        return known
    try:
        with open(path, "rb") as handle:
            first = handle.readline(200)
    except OSError:
        return None
    if first.startswith(b"#!"):
        if b"python" in first:
            return "python"
        if re.search(rb"\b(?:ba|z|k|da)?sh\b", first):
            return "shell"
    return None


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _python_defs(tree):
    """Return (qualified name, node, depth) for every function and class."""
    found = []

    def walk(node, prefix, depth):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                found.append((prefix + child.name, child, depth))
                walk(child, prefix + child.name + ".", depth + 1)
            else:
                walk(child, prefix, depth)

    walk(tree, "", 0)
    return found


def _python_items(tree):
    defs = _python_defs(tree)
    known = {name.split(".")[-1] for name, _, _ in defs}
    items = []
    for name, node, depth in defs:
        start = min([node.lineno] + [item.lineno for item in node.decorator_list])
        calls = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                target = getattr(sub.func, "id", None) or getattr(sub.func, "attr", None)
                if target in known and target not in calls and target != name.split(".")[-1]:
                    calls.append(target)
        if isinstance(node, ast.ClassDef):
            items.append(Item(name, start, node.end_lineno, "", calls, depth, "class"))
        else:
            spec = node.args
            names = [arg.arg for arg in spec.posonlyargs + spec.args + spec.kwonlyargs]
            names += ["*" + arg.arg for arg in (spec.vararg, spec.kwarg) if arg]
            items.append(Item(name, start, node.end_lineno, ", ".join(names), calls, depth))
    return items


def _python_header(tree):
    imports, names = [], []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports += [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imports.append("." * node.level + (node.module or ""))
        elif isinstance(node, ast.Assign):
            names += [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.append(node.target.id)
    return sorted(set(imports)), names


def _shell_code(line):
    code = blank_quotes(line)
    found = re.search(r"(?:^|\s)#", code)
    return code[: found.start()] if found else code


def _shell_items(lines):
    items = []
    for number, line in enumerate(lines, 1):
        found = _SH_DEF[0].match(line) or _SH_DEF[1].match(line)
        if not found:
            continue
        depth, opened, end = 0, False, len(lines)
        for row in range(number - 1, len(lines)):
            code = _shell_code(lines[row])
            depth += code.count("{") - code.count("}")
            opened = opened or "{" in code
            if opened and depth <= 0:
                end = row + 1
                break
        items.append(Item(found.group(1), number, end))
    names = [item.name for item in items]
    for item in items:
        body = "\n".join(lines[item.start : item.end])
        item.calls = [
            name for name in names
            if name != item.name and re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(name), body)
        ]
    return items


def _items(path, source):
    if language(path) == "python":
        return _python_items(ast.parse(source))
    return _shell_items(source.splitlines())


def outline(path, name_filter=None):
    """Return the outline of a file as lines of text. It never shows function bodies."""
    source = _read(path)
    out = ["%s  %d lines" % (path, len(source.splitlines()))]
    if language(path) == "python":
        imports, names = _python_header(ast.parse(source))
        if imports:
            out.append("imports: " + ", ".join(imports))
        if names:
            out.append("globals: " + ", ".join(names))
    for item in _items(path, source):
        if name_filter and name_filter not in item.name:
            continue
        calls = "  -> " + ", ".join(item.calls) if item.calls else ""
        args = "(%s)" % item.args if item.kind == "def" else ""
        out.append("%s%s L%d-%d %s%s%s" % ("  " * item.depth, item.kind, item.start, item.end, item.name, args, calls))
    return out


def _hide_string(token):
    found = _STRING_START.match(token)
    prefix, quote = (found.group(1), found.group(2)) if found else ("", '"')
    return prefix + quote + "..." + quote


def _quiet_python(source, keep_strings):
    lines = source.splitlines()
    middle = getattr(tokenize, "FSTRING_MIDDLE", None)
    edits = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                edits.append((token.start, token.end, ""))
            elif keep_strings:
                continue
            elif token.type == tokenize.STRING:
                edits.append((token.start, token.end, _hide_string(token.string)))
            elif middle is not None and token.type == middle and token.string.strip():
                edits.append((token.start, token.end, "..."))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return _quiet_shell(lines, keep_strings)
    for (first, start), (last, end), text in reversed(edits):
        lines[first - 1] = lines[first - 1][:start] + text + lines[last - 1][end:]
        for row in range(first, last):
            lines[row] = ""
    return lines


def _hide_shell_string(match):
    text = match.group(0)
    return text if _SH_PLAIN_VAR.match(text) else text[0] + "..." + text[0]


def _quiet_shell(lines, keep_strings):
    out = []
    for line in lines:
        found = re.search(r"(?:^|\s)#", blank_quotes(line))
        if found and not line.startswith("#!"):
            line = line[: found.start()]
        out.append(line if keep_strings else _SH_STRING.sub(_hide_shell_string, line))
    return out


def peek(path, what, keep_strings=False, raw=False):
    """Return numbered lines of one function, class or start:end range.

    Comments are dropped and strings shown as "..." unless asked otherwise, which
    keeps the output short and leaves out any value someone pasted into a string.
    """
    source = _read(path)
    lines = source.splitlines()
    span = re.fullmatch(r"([0-9]+):([0-9]+)", what)
    if span:
        ranges = [(int(span.group(1)), int(span.group(2)))]
    else:
        items = _items(path, source)
        ranges = [
            (item.start, item.end) for item in items if what in (item.name, item.name.split(".")[-1])
        ]
    if raw:
        shown = lines
    elif language(path) == "python":
        shown = _quiet_python(source, keep_strings)
    else:
        shown = _quiet_shell(lines, keep_strings)
    out = []
    for start, end in ranges:
        for number in range(start, min(end, len(lines)) + 1):
            text = shown[number - 1].rstrip()
            if raw or text.strip():
                out.append("%6d  %s" % (number, text))
    return out


def _source_files(root):
    if os.path.isfile(root):
        yield root
        return
    for folder, subfolders, names in os.walk(root):
        subfolders[:] = sorted(name for name in subfolders if name not in SKIP_DIRS)
        for name in sorted(names):
            if os.path.splitext(name)[1].lower() in LANGUAGES:
                yield os.path.join(folder, name)


def references(root, name):
    """Return `path:line  enclosing` for each use of name. Line contents stay out."""
    pattern = re.compile(r"(?<!\w)%s(?!\w)" % re.escape(name))
    out = []
    for path in _source_files(root):
        source = _read(path)
        try:
            items = _items(path, source)
        except SyntaxError:
            items = []
        label = os.path.relpath(path, root) if os.path.isdir(root) else path
        for number, line in enumerate(source.splitlines(), 1):
            if pattern.search(line):
                inside = [item for item in items if item.start <= number <= item.end]
                where = max(inside, key=lambda item: item.start).name if inside else "<top level>"
                out.append("%s:%d  %s" % (label, number, where))
    return out


def _shell_comment_above(lines, line):
    found = []
    row = line - 2
    while row >= 0 and lines[row].lstrip().startswith("#") and not lines[row].startswith("#!"):
        found.insert(0, lines[row].lstrip("# \t"))
        row -= 1
    return "\n".join(found)


def docs(path, name=None):
    """Return docstrings (Python) or the comment above each function (shell)."""
    source = _read(path)
    out = []
    if language(path) == "python":
        tree = ast.parse(source)
        if name is None and ast.get_docstring(tree):
            out.append(ast.get_docstring(tree))
        for label, node, _ in _python_defs(tree):
            text = ast.get_docstring(node)
            if text and name in (None, label, label.split(".")[-1]):
                out.append("%s: %s" % (label, text if name else text.splitlines()[0]))
    else:
        lines = source.splitlines()
        for item in _shell_items(lines):
            text = _shell_comment_above(lines, item.start)
            if text and name in (None, item.name):
                out.append("%s: %s" % (item.name, text))
    return out
