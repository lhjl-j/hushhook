import json
import os
import re
import unittest

from support import ROOT
import hushhook
from hushhook import scan
from hushhook.rules import load_rules

SKIP_DIRS = {".git", "__pycache__", "build", "dist", ".venv"}


def repo_files():
    for folder, subfolders, names in os.walk(ROOT):
        subfolders[:] = [name for name in subfolders if name not in SKIP_DIRS and not name.endswith(".egg-info")]
        for name in names:
            if not name.endswith(".pyc"):
                yield os.path.join(folder, name)


def load_json(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return json.load(handle)


class Repository(unittest.TestCase):
    def test_nothing_here_looks_like_a_real_secret(self):
        # GitHub refuses a push that holds one, so catch it before you get there.
        rules = load_rules({}, kinds=("secrets",)).secrets
        found = []
        for path in repo_files():
            with open(path, encoding="utf-8", errors="replace") as handle:
                hits = scan.find(handle.read(), rules)
            found += ["%s: %s" % (os.path.relpath(path, ROOT), rule_id) for rule_id in hits]
        self.assertEqual(found, [])

    def test_versions_agree(self):
        self.assertEqual(load_json(".claude-plugin", "plugin.json")["version"], hushhook.__version__)
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as handle:
            self.assertIn("## " + hushhook.__version__, handle.read())

    def test_plugin_hooks_call_the_hook_module(self):
        hooks = load_json("hooks", "hooks.json")["hooks"]
        pre = hooks["PreToolUse"][0]
        self.assertEqual(pre["matcher"], "Read|Bash")
        self.assertTrue(pre["hooks"][0]["command"].endswith("-m hushhook.hook pre"))
        self.assertTrue(hooks["PostToolUse"][0]["hooks"][0]["command"].endswith("-m hushhook.hook post"))

    def test_plugin_and_marketplace_share_a_name(self):
        plugin = load_json(".claude-plugin", "plugin.json")
        market = load_json(".claude-plugin", "marketplace.json")
        self.assertEqual(market["plugins"][0]["name"], plugin["name"])

    def test_the_plugin_shim_is_executable(self):
        self.assertTrue(os.access(os.path.join(ROOT, "bin", "hushhook"), os.X_OK))

    def test_rule_files_are_named_after_their_ecosystem(self):
        for path in repo_files():
            if path.endswith(".rules"):
                self.assertRegex(os.path.basename(path), re.compile(r"^[a-z0-9-]+\.rules$"))


if __name__ == "__main__":
    unittest.main()
