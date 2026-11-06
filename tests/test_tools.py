import json
import os
import shutil
import tempfile
import unittest
from urllib.parse import parse_qs, urlparse

import support
from hushhook import tools


class Base(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)
        self.settings = os.path.join(self.home, ".config", "hushhook", "config.json")
        self.root = os.path.join(self.home, ".config", "hushhook", "rules")

    def run_cli(self, *args):
        return support.run_module(["hushhook"] + list(args), self.home)

    def rule_path(self, kind, rule_id):
        return os.path.join(self.root, kind, rule_id + ".rules")


class Explain(Base):
    def test_known_rule(self):
        result = self.run_cli("explain", "dotenv")
        self.assertEqual(result.returncode, 0, result.stderr)
        for text in ("Rule:     dotenv", "Kind:     files", "env.rules", self.settings, "disabled"):
            self.assertIn(text, result.stdout)
        self.assertIn("issues/new?template=wrong_match.yml&title=Wrong%20match%3A%20dotenv", result.stdout)

    def test_command_rule_shows_reason(self):
        result = self.run_cli("explain", "git-force-push")
        self.assertIn("Reason:", result.stdout)

    def test_unknown_rule_suggests_three(self):
        result = self.run_cli("explain", "dotenvv")
        self.assertEqual(result.returncode, 1)
        self.assertIn("No rule with the id dotenvv", result.stderr)
        closest = result.stderr.split("Closest ids:")[1].strip().split(", ")
        self.assertEqual(len(closest), 3)
        self.assertIn("dotenv", closest)

    def test_link_has_only_the_id(self):
        query = parse_qs(urlparse(tools.issue_link("dotenv")).query)
        self.assertEqual(query["title"], ["Wrong match: dotenv"])
        self.assertEqual(set(query), {"template", "title"})


class DenyMessage(Base):
    def pre(self, tool, tool_input):
        payload = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "cwd": self.home}
        return support.answer(support.run_hook("pre", payload, self.home))

    def reason(self, answer):
        return answer["hookSpecificOutput"]["permissionDecisionReason"]

    def test_file_deny_has_hint_at_the_end(self):
        reason = self.reason(self.pre("Read", {"file_path": os.path.join(self.home, ".env")}))
        self.assertIn("(rule dotenv)", reason)
        self.assertTrue(reason.endswith("If this looks wrong, the user can run: hushhook explain dotenv"))

    def test_command_deny_has_hint_at_the_end(self):
        reason = self.reason(self.pre("Bash", {"command": "git push --force origin main"}))
        self.assertIn("ask the user to run it.", reason)
        self.assertTrue(reason.endswith("hushhook explain git-force-push"))


class RulesNew(Base):
    def test_creates_file_and_settings(self):
        result = self.run_cli("rules", "new", "secrets", "acme-svc")
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(self.rule_path("secrets", "acme-svc"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("# id: acme-svc", text)
        self.assertIn("# matches:", text)
        self.assertIn("# ignores:", text)
        with open(self.settings, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["extra_rule_dirs"], [self.root])
        self.assertEqual(self.run_cli("rules", "test").returncode, 0)

    def test_every_kind_works(self):
        for kind in ("secrets", "files", "commands"):
            self.assertEqual(self.run_cli("rules", "new", kind, "my-" + kind).returncode, 0)

    def test_keeps_other_settings(self):
        os.makedirs(os.path.dirname(self.settings))
        with open(self.settings, "w", encoding="utf-8") as handle:
            json.dump({"max_read_lines": 50, "disabled": ["dotenv"], "extra_rule_dirs": ["~/other"]}, handle)
        self.assertEqual(self.run_cli("rules", "new", "files", "acme-file").returncode, 0)
        with open(self.settings, encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(data["max_read_lines"], 50)
        self.assertEqual(data["disabled"], ["dotenv"])
        self.assertEqual(data["extra_rule_dirs"], ["~/other", self.root])

    def test_settings_untouched_when_already_loaded(self):
        os.makedirs(os.path.dirname(self.settings))
        text = json.dumps({"extra_rule_dirs": ["~/.config/hushhook/rules"]})
        with open(self.settings, "w", encoding="utf-8") as handle:
            handle.write(text)
        self.run_cli("rules", "new", "files", "acme-file")
        with open(self.settings, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), text)

    def test_bad_input(self):
        for args in (("bogus", "acme"), ("secrets", "Acme"), ("secrets", "acme_x"), ("secrets", "a-"), ("secrets",)):
            self.assertEqual(self.run_cli("rules", "new", *args).returncode, 1, args)
        self.assertFalse(os.path.exists(self.root))

    def test_builtin_id_refused(self):
        result = self.run_cli("rules", "new", "secrets", "dotenv")
        self.assertEqual(result.returncode, 1)
        self.assertIn("built-in", result.stderr)
        self.assertFalse(os.path.exists(self.rule_path("secrets", "dotenv")))

    def test_never_overwrites(self):
        self.run_cli("rules", "new", "secrets", "acme-svc")
        path = self.rule_path("secrets", "acme-svc")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("mine\n")
        result = self.run_cli("rules", "new", "secrets", "acme-svc")
        self.assertEqual(result.returncode, 0)
        self.assertIn(path, result.stdout)
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "mine\n")


class RulesShare(Base):
    def write(self, kind, rule_id, text):
        path = self.rule_path(kind, rule_id)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)

    def test_good_rule_prints_encoded_link(self):
        text = "id: acme-svc\npattern: \\bacme_[A-Za-z0-9]{36}\\b\nmatches: acme_{a*36}\nignores: acme_short\n"
        self.write("secrets", "acme-svc", text)
        result = self.run_cli("rules", "share", "acme-svc")
        self.assertEqual(result.returncode, 0, result.stderr)
        link = [line for line in result.stdout.splitlines() if line.startswith("https://")][0]
        parsed = urlparse(link)
        self.assertEqual(parsed.path, "/monarchsofchaos004-gif/hushhook/new/main/hushhook/rules/secrets")
        self.assertNotIn(" ", link)
        self.assertIn("%0A", link)
        query = parse_qs(parsed.query)
        self.assertEqual(query["filename"], ["acme-svc.rules"])
        self.assertEqual(query["value"], [text])

    def test_failing_example_is_reported(self):
        self.write("secrets", "acme-svc", "id: acme-svc\npattern: \\bacme_[A-Za-z0-9]{36}\\b\nmatches: acme_short\n")
        result = self.run_cli("rules", "share", "acme-svc")
        self.assertEqual(result.returncode, 1)
        self.assertIn("should match but does not: acme_short", result.stderr)
        self.assertNotIn("https://", result.stdout)

    def test_unedited_template_is_not_ready(self):
        self.run_cli("rules", "new", "secrets", "acme-svc")
        result = self.run_cli("rules", "share", "acme-svc")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no rule with id acme-svc", result.stderr)

    def test_secret_like_example_refused(self):
        # An example that expands to a known secret format must not leave the machine.
        self.write("secrets", "my-copy", "id: my-copy\npattern: ghp_[A-Za-z0-9]{36}\nmatches: ghp_{a*36}\n")
        result = self.run_cli("rules", "share", "my-copy")
        self.assertEqual(result.returncode, 1)
        self.assertIn("looks like a real secret", result.stderr)
        self.assertNotIn("https://", result.stdout)

    def test_literal_secret_in_file_refused(self):
        literal = "ghp_" + "a" * 36
        self.write("secrets", "acme-svc", "# %s\nid: acme-svc\npattern: acme_x\nmatches: acme_x\n" % literal)
        result = self.run_cli("rules", "share", "acme-svc")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(literal, result.stdout + result.stderr)

    def test_missing_file(self):
        self.assertEqual(self.run_cli("rules", "share", "nothing-here").returncode, 1)


if __name__ == "__main__":
    unittest.main()
