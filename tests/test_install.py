import json
import os
import subprocess
import tempfile
import unittest

from support import clean_env, run_module


class Install(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.home = os.path.realpath(self.folder.name)
        self.path = os.path.join(self.home, ".claude", "settings.json")

    def cli(self, *args, cwd=None, env=None):
        return run_module(["hushhook"] + list(args), self.home, cwd=cwd, env=env)

    def write_settings(self, data, path=None):
        path = path or self.path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            if isinstance(data, str):
                handle.write(data)
            else:
                json.dump(data, handle)

    def settings(self, path=None):
        with open(path or self.path, encoding="utf-8") as handle:
            return json.load(handle)

    def backups(self, path=None):
        path = path or self.path
        folder, name = os.path.split(path)
        return [item for item in os.listdir(folder) if item.startswith(name + ".hushhook-backup-")]

    def our_entries(self, settings):
        return [
            entry
            for groups in settings.get("hooks", {}).values()
            for group in groups
            for entry in group["hooks"]
            if "hushhook.hook" in entry["command"]
        ]

    def test_creates_settings_when_there_are_none(self):
        result = self.cli("install")
        self.assertEqual(result.returncode, 0, result.stderr)
        hooks = self.settings()["hooks"]
        self.assertEqual(hooks["PreToolUse"][0]["matcher"], "Read|Bash")
        self.assertEqual(hooks["PostToolUse"][0]["matcher"], "*")
        self.assertTrue(hooks["PreToolUse"][0]["hooks"][0]["command"].endswith("hushhook.hook pre"))
        self.assertTrue(hooks["PostToolUse"][0]["hooks"][0]["command"].endswith("hushhook.hook post"))
        self.assertEqual(self.backups(), [])

    def test_merges_and_backs_up(self):
        other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-own-hook"}]}
        original = {"model": "demo", "permissions": {"allow": ["Bash(ls)"]}, "hooks": {"PreToolUse": [other]}}
        self.write_settings(original)
        self.assertEqual(self.cli("install").returncode, 0)
        settings = self.settings()
        self.assertEqual(settings["model"], "demo")
        self.assertEqual(settings["permissions"], {"allow": ["Bash(ls)"]})
        self.assertEqual(settings["hooks"]["PreToolUse"][0], other)
        self.assertEqual(len(settings["hooks"]["PreToolUse"]), 2)
        backups = self.backups()
        self.assertEqual(len(backups), 1)
        self.assertEqual(self.settings(os.path.join(os.path.dirname(self.path), backups[0])), original)

    def test_running_it_again_changes_nothing(self):
        self.write_settings({"model": "demo"})
        self.cli("install")
        first = self.settings()
        result = self.cli("install")
        self.assertEqual(result.returncode, 0)
        self.assertIn("nothing changed", result.stdout)
        self.assertEqual(self.settings(), first)
        self.assertEqual(len(self.our_entries(first)), 2)
        self.assertEqual(len(self.backups()), 1)

    def test_a_moved_install_is_refreshed_not_duplicated(self):
        self.cli("install")
        settings = self.settings()
        for entry in self.our_entries(settings):
            entry["command"] = "/old/python -m hushhook.hook pre"
        self.write_settings(settings)
        self.cli("install")
        entries = self.our_entries(self.settings())
        self.assertEqual(len(entries), 2)
        self.assertFalse(any("/old/python" in entry["command"] for entry in entries))

    def test_uninstall_takes_out_only_what_it_added(self):
        other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "my-own-hook"}]}
        extra = {"Stop": [{"hooks": [{"type": "command", "command": "stop-hook"}]}]}
        hooks = dict(extra, PreToolUse=[other])
        self.write_settings({"model": "demo", "hooks": hooks})
        self.cli("install")
        result = self.cli("uninstall")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.settings(), {"model": "demo", "hooks": hooks})

    def test_uninstall_keeps_a_neighbour_in_the_same_group(self):
        self.cli("install")
        settings = self.settings()
        settings["hooks"]["PreToolUse"][0]["hooks"].append({"type": "command", "command": "my-own-hook"})
        self.write_settings(settings)
        self.cli("uninstall")
        kept = self.settings()["hooks"]["PreToolUse"][0]["hooks"]
        self.assertEqual(kept, [{"type": "command", "command": "my-own-hook"}])

    def test_uninstall_leaves_no_empty_shells(self):
        self.cli("install")
        self.cli("uninstall")
        self.assertEqual(self.settings(), {})

    def test_uninstall_with_nothing_to_do(self):
        self.write_settings({"model": "demo"})
        result = self.cli("uninstall")
        self.assertEqual(result.returncode, 0)
        self.assertIn("Nothing to remove", result.stdout)
        self.assertEqual(self.backups(), [])

    def test_project_flag_stays_in_the_project(self):
        project = os.path.join(self.home, "project")
        os.makedirs(project)
        self.assertEqual(self.cli("install", "--project", cwd=project).returncode, 0)
        path = os.path.join(project, ".claude", "settings.json")
        self.assertEqual(len(self.our_entries(self.settings(path))), 2)
        self.assertFalse(os.path.exists(self.path))
        self.cli("uninstall", "--project", cwd=project)
        self.assertEqual(self.settings(path), {})

    def test_settings_it_cannot_read_are_left_untouched(self):
        for broken in ("{ not json", "[]", '{"hooks": []}', '{"hooks": {"PreToolUse": {}}}'):
            with self.subTest(broken=broken):
                self.write_settings(broken)
                for command in ("install", "uninstall"):
                    result = self.cli(command)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("untouched", result.stderr)
                with open(self.path, encoding="utf-8") as handle:
                    self.assertEqual(handle.read(), broken)
                self.assertEqual(self.backups(), [])

    def test_file_permissions_are_kept(self):
        self.write_settings({})
        os.chmod(self.path, 0o600)
        self.cli("install")
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_custom_config_folder(self):
        folder = os.path.join(self.home, "other-config")
        env = clean_env(self.home)
        env["CLAUDE_CONFIG_DIR"] = folder
        self.assertEqual(self.cli("install", env=env).returncode, 0)
        path = os.path.join(folder, "settings.json")
        self.assertEqual(len(self.our_entries(self.settings(path))), 2)
        self.assertFalse(os.path.exists(self.path))

    def test_the_installed_command_really_runs(self):
        self.cli("install")
        command = self.settings()["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "cat .env"}, "cwd": self.home})
        env = clean_env(self.home)
        env.pop("PYTHONPATH")
        result = subprocess.run(
            ["sh", "-c", command], input=payload, capture_output=True, text=True, env=env, cwd=self.home, timeout=60
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_doctor_is_happy_on_a_clean_machine(self):
        self.cli("install")
        result = self.cli("doctor")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("FAIL", result.stdout)
        self.assertIn(self.path + ": installed", result.stdout)

    def test_doctor_reports_a_bad_config(self):
        folder = os.path.join(self.home, ".config", "hushhook")
        os.makedirs(folder)
        with open(os.path.join(folder, "config.json"), "w", encoding="utf-8") as handle:
            handle.write('{"max_read_lines": "many", "typo": 1}')
        result = self.cli("doctor")
        self.assertEqual(result.returncode, 1)
        self.assertIn("max_read_lines", result.stdout)
        self.assertIn("unknown setting: typo", result.stdout)

    def test_rules_commands(self):
        listing = self.cli("rules").stdout
        self.assertIn("github-classic-token", listing)
        self.assertIn("dotenv", listing)
        self.assertIn("git-force-push", listing)
        result = self.cli("rules", "test")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("all examples pass", result.stdout)

    def test_rules_test_fails_on_a_wrong_example(self):
        folder = os.path.join(self.home, "mine", "secrets")
        os.makedirs(folder)
        with open(os.path.join(folder, "mine.rules"), "w", encoding="utf-8") as handle:
            handle.write("id: my-token\npattern: abc_[0-9]{4}\nmatches: abc_{1*3}\n")
        config = os.path.join(self.home, ".config", "hushhook")
        os.makedirs(config)
        with open(os.path.join(config, "config.json"), "w", encoding="utf-8") as handle:
            json.dump({"extra_rule_dirs": [os.path.dirname(folder)]}, handle)
        result = self.cli("rules", "test")
        self.assertEqual(result.returncode, 1)
        self.assertIn("my-token", result.stdout)
        self.assertIn("abc_{1*3}", result.stdout)

    def test_mask_and_leaks_commands(self):
        self.assertEqual(run_module(["hushhook", "mask"], self.home, "plain\n").stdout, "plain\n")
        self.assertIn("No possible secrets", self.cli("leaks").stdout)


if __name__ == "__main__":
    unittest.main()
