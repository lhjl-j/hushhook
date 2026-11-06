import os
import tempfile
import unittest

from support import run_module
from hushhook import codemap

PYTHON = '''"""Module note."""
import os
from pathlib import Path

LIMIT = 5


def load(path, *rest):
    """Read a file."""
    # a private remark
    value = "kept out of sight"
    return clean(value)


def clean(text):
    return text.strip()


class Store:
    """Keeps things."""

    @staticmethod
    def get(key):
        return load(key)
'''

SHELL = """#!/bin/sh
# Greets someone.
greet() {
  echo "hello there"  # a private remark
  helper "$1"
}

function helper {
  printf '%s\\n' "$1"
}

one_line() { echo "${HOME}"; }
"""


class CodeMap(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.home = os.path.realpath(self.folder.name)
        self.python = self.write("app.py", PYTHON)
        self.shell = self.write("run.sh", SHELL)

    def write(self, name, text):
        path = os.path.join(self.home, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_python_outline(self):
        text = "\n".join(codemap.outline(self.python))
        self.assertIn("imports: os, pathlib", text)
        self.assertIn("globals: LIMIT", text)
        self.assertIn("def L8-12 load(path, *rest)  -> clean", text)
        self.assertIn("class L19-24 Store", text)
        self.assertIn("  def L22-24 Store.get(key)  -> load", text)
        self.assertNotIn("kept out of sight", text)

    def test_outline_filter(self):
        text = "\n".join(codemap.outline(self.python, "Store"))
        self.assertIn("Store.get", text)
        self.assertNotIn("def L8-12", text)

    def test_shell_outline(self):
        text = "\n".join(codemap.outline(self.shell))
        self.assertIn("def L3-6 greet()  -> helper", text)
        self.assertIn("def L8-10 helper()", text)
        self.assertIn("def L12-12 one_line()", text)

    def test_peek_hides_comments_and_strings(self):
        text = "\n".join(codemap.peek(self.python, "load"))
        self.assertIn("return clean(value)", text)
        self.assertIn('value = "..."', text)
        self.assertNotIn("kept out of sight", text)
        self.assertNotIn("private remark", text)

    def test_peek_keeps_real_line_numbers(self):
        self.assertTrue(codemap.peek(self.python, "clean")[0].lstrip().startswith("15"))

    def test_peek_keep_strings(self):
        text = "\n".join(codemap.peek(self.python, "load", keep_strings=True))
        self.assertIn("kept out of sight", text)
        self.assertNotIn("private remark", text)

    def test_peek_raw(self):
        text = "\n".join(codemap.peek(self.python, "load", raw=True))
        self.assertIn("kept out of sight", text)
        self.assertIn("private remark", text)

    def test_peek_range_and_method(self):
        self.assertIn("LIMIT", codemap.peek(self.python, "5:5")[0])
        self.assertIn("staticmethod", codemap.peek(self.python, "get")[0])
        self.assertIn("staticmethod", codemap.peek(self.python, "Store.get")[0])

    def test_peek_shell(self):
        text = "\n".join(codemap.peek(self.shell, "greet"))
        self.assertIn('echo "..."', text)
        self.assertIn('helper "$1"', text)
        self.assertNotIn("hello there", text)
        self.assertNotIn("private remark", text)

    def test_refs_show_place_not_content(self):
        lines = codemap.references(self.home, "load")
        self.assertIn("app.py:8  load", lines)
        self.assertIn("app.py:24  Store.get", lines)
        self.assertFalse(any("return" in line for line in lines))

    def test_refs_in_shell(self):
        self.assertIn("run.sh:5  greet", codemap.references(self.home, "helper"))

    def test_refs_skip_cache_folders(self):
        os.makedirs(os.path.join(self.home, "node_modules"))
        self.write(os.path.join("node_modules", "x.py"), "load\n")
        self.assertFalse(any("node_modules" in line for line in codemap.references(self.home, "load")))

    def test_docs(self):
        text = "\n".join(codemap.docs(self.python))
        self.assertIn("Module note.", text)
        self.assertIn("load: Read a file.", text)
        self.assertIn("Store: Keeps things.", text)
        self.assertEqual(codemap.docs(self.python, "load"), ["load: Read a file."])
        self.assertEqual(codemap.docs(self.shell, "greet"), ["greet: Greets someone."])

    def test_language_from_the_first_line(self):
        self.assertEqual(codemap.language(self.write("tool", "#!/usr/bin/env python3\n")), "python")
        self.assertEqual(codemap.language(self.write("job", "#!/bin/bash\n")), "shell")
        self.assertIsNone(codemap.language(self.write("notes", "plain\n")))

    def cli(self, *args):
        return run_module(["hushhook"] + list(args), self.home)

    def test_command_line(self):
        self.assertIn("def L8-12 load", self.cli("map", "app.py").stdout)
        self.assertIn("return clean(value)", self.cli("peek", "app.py", "load").stdout)
        self.assertIn("app.py:8  load", self.cli("refs", ".", "load").stdout)
        self.assertIn("load: Read a file.", self.cli("doc", "app.py").stdout)

    def test_command_line_says_when_nothing_was_found(self):
        self.assertEqual(self.cli("peek", "app.py", "missing").returncode, 1)
        self.assertEqual(self.cli("map", "nope.py").returncode, 1)
        self.assertEqual(self.cli("refs", ".", "missing").returncode, 1)

    def test_other_languages_get_a_clear_message(self):
        self.write("page.ts", "const a = 1;\n")
        result = self.cli("map", "page.ts")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not Python or shell yet", result.stderr)

    def test_a_file_that_does_not_parse(self):
        self.write("bad.py", "def (:\n")
        result = self.cli("map", "bad.py")
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not parse", result.stderr)

    def test_secret_files_stay_closed(self):
        self.write("secrets.py", "x = 1\n")
        self.write(".env", "KEY=value\n")
        for args in (("peek", ".env", "1:1"), ("peek", ".env", "1:1", "--raw"), ("map", ".env"), ("doc", ".env")):
            with self.subTest(args=args):
                result = self.cli(*args)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertIn("dotenv", result.stderr)


if __name__ == "__main__":
    unittest.main()
