import json
import os
import stat
import subprocess
import tempfile
import unittest

from support import answer, clean_env, run_hook, run_module
from hushhook.rules import expand, load_rules

TOKEN = expand("ghp_{a*36}")


class HookCase(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.home = os.path.realpath(self.folder.name)
        self.big = self.write("big.log", "line\n" * 1000)
        self.small = self.write("small.txt", "line\n" * 10)

    def write(self, name, text, mode="w"):
        path = os.path.join(self.home, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, mode) as handle:
            handle.write(text)
        return path

    def config(self, **settings):
        self.write(".config/hushhook/config.json", json.dumps(settings))

    def call(self, event, payload):
        result = run_hook(event, payload, self.home)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        return answer(result)

    def pre(self, tool, tool_input, **extra):
        payload = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "cwd": self.home}
        payload.update(extra)
        return self.call("pre", payload)

    def post(self, tool, response):
        payload = {"hook_event_name": "PostToolUse", "tool_name": tool, "tool_input": {}, "tool_response": response}
        return self.call("post", payload)

    def assertDenied(self, reply, expected):
        self.assertIsNotNone(reply, "expected a deny")
        output = reply["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn(expected, output["permissionDecisionReason"])


class ReadGate(HookCase):
    def read(self, path, **extra):
        tool_input = {"file_path": path}
        tool_input.update(extra)
        return self.pre("Read", tool_input)

    def test_secret_files_are_denied(self):
        for name, rule in ((".env", "dotenv"), ("app/.env.local", "dotenv"), ("server.pem", "pem-file")):
            with self.subTest(name=name):
                self.assertDenied(self.read(self.write(name, "x\n")), rule)

    def test_a_template_env_file_is_fine(self):
        self.assertIsNone(self.read(self.write(".env.example", "KEY=\n")))

    def test_a_symlink_to_a_secret_file_is_denied(self):
        target = self.write(".env", "KEY=1\n")
        link = os.path.join(self.home, "harmless.txt")
        os.symlink(target, link)
        self.assertDenied(self.read(link), "dotenv")

    def test_big_file_without_limit_is_denied(self):
        self.assertDenied(self.read(self.big), "hushhook map")

    def test_big_file_with_limit_is_fine(self):
        self.assertIsNone(self.read(self.big, offset=100, limit=50))

    def test_a_huge_limit_is_not_a_limit(self):
        self.assertDenied(self.read(self.big, limit=5000), "hushhook map")

    def test_small_file_is_fine(self):
        self.assertIsNone(self.read(self.small))

    def test_binary_file_is_fine(self):
        self.assertIsNone(self.read(self.write("image.bin", b"\0\n" * 1000, "wb")))

    def test_max_read_lines_comes_from_the_config(self):
        self.config(max_read_lines=5)
        self.assertDenied(self.read(self.small), "more than 5 lines")

    def test_a_named_pipe_does_not_hang(self):
        path = os.path.join(self.home, "pipe")
        os.mkfifo(path)
        self.assertIsNone(self.read(path))

    def test_missing_file_is_left_to_the_tool(self):
        self.assertIsNone(self.read(os.path.join(self.home, "nope.txt")))


class BashGate(HookCase):
    def bash(self, command, **extra):
        return self.pre("Bash", {"command": command}, permission_mode="bypassPermissions", **extra)

    def assertRewritten(self, reply):
        self.assertIsNotNone(reply, "expected a rewrite")
        self.assertIn("updatedInput", reply["hookSpecificOutput"])

    def test_every_commands_rule_denies_with_its_reason(self):
        for rule in load_rules({}, kinds=("commands",)).commands:
            with self.subTest(rule=rule.id):
                self.assertDenied(self.bash(expand(rule.matches[0])), rule.id)

    def test_the_reason_explains_the_danger(self):
        rule = next(rule for rule in load_rules({}, kinds=("commands",)).commands if rule.id == "git-force-push")
        self.assertDenied(self.bash("git push --force origin main"), rule.reason)

    def test_disabled_commands_rule_lets_the_command_through(self):
        self.config(disabled=["git-force-push"])
        self.assertRewritten(self.bash("git push --force origin main"))

    def test_dumping_secret_files_is_denied(self):
        commands = (
            "cat .env",
            "head -3 .env",
            "tail -n 5 ~/.aws/credentials",
            "sed -n 1,5p .env",
            "less id_rsa",
            "grep KEY .env",
            "echo hi; cat .env",
            "cat < .env",
            "sudo cat .env",
            "FOO=1 cat .env",
            "cat .en*",
            "echo $(cat .env)",
            "cd app && cat .env",
            "base64 id_rsa",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertDenied(self.bash(command), "usually holds secrets")

    def test_mentioning_a_secret_file_is_fine(self):
        for command in ("ls -la .env", "grep .env README.md", "chmod 600 .env", "echo '.env'", "git add .gitignore"):
            with self.subTest(command=command):
                self.assertRewritten(self.bash(command))

    def test_big_dumps_are_denied(self):
        commands = (
            "cat big.log",
            "cat small.txt big.log",
            "cat big.log | tee copy.log",
            "cat big.log 2>/dev/null",
            "sed -n '1,500p' big.log",
            "sed -n 1,500p big.log",
            "sed -n '100,$p' big.log",
            "head -n 500 big.log",
            "head -500 big.log",
            "head -n500 big.log",
            "head --lines=500 big.log",
            "tail -n 500 big.log",
            "tail -500 big.log",
            "tail -n +1 big.log",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertDenied(self.bash(command), "big dump")

    def test_filtered_or_small_reads_are_fine(self):
        commands = (
            "cat big.log | grep error",
            "cat big.log | wc -l",
            "cat big.log > copy.log",
            "cat small.txt",
            "sed -n '1,100p' big.log",
            "sed 's/a/b/' small.txt",
            "head -n 50 big.log",
            "tail -20 big.log",
            "tail -n 500 small.txt",
            "head -n 500 big.log | grep error",
            "tail -f big.log",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertRewritten(self.bash(command))

    def test_big_dump_follows_a_leading_cd(self):
        self.write("logs/app.log", "line\n" * 1000)
        self.assertDenied(self.bash("cd logs && cat app.log"), "big dump")

    def test_bypass_mode_rewrites_and_allows(self):
        tool_input = {"command": "ls", "description": "List files", "timeout": 5000, "run_in_background": False}
        reply = self.pre("Bash", tool_input, permission_mode="bypassPermissions")
        output = reply["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "allow")
        updated = output["updatedInput"]
        self.assertIn("hushhook.mask", updated.pop("command"))
        tool_input.pop("command")
        self.assertEqual(updated, tool_input)

    def test_the_rewritten_command_really_runs_on_its_own(self):
        reply = self.bash("echo %s; exit 7" % TOKEN)
        env = clean_env(self.home)
        env.pop("PYTHONPATH")
        result = subprocess.run(
            ["bash", "-c", reply["hookSpecificOutput"]["updatedInput"]["command"]],
            capture_output=True,
            text=True,
            env=env,
            cwd=self.home,
            timeout=60,
        )
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "[hushhook:github-classic-token]\n")

    def test_modes_that_prompt_are_not_rewritten_by_default(self):
        for mode in ("default", "acceptEdits", "plan", "auto", "dontAsk"):
            with self.subTest(mode=mode):
                self.assertIsNone(self.pre("Bash", {"command": "ls"}, permission_mode=mode))

    def test_always_rewrites_but_never_approves_for_the_user(self):
        self.config(wrap_bash="always")
        reply = self.pre("Bash", {"command": "ls"}, permission_mode="default")
        self.assertIn("updatedInput", reply["hookSpecificOutput"])
        self.assertNotIn("permissionDecision", reply["hookSpecificOutput"])

    def test_unknown_mode_rewrites_but_never_approves_for_the_user(self):
        reply = self.pre("Bash", {"command": "ls"})
        self.assertIn("updatedInput", reply["hookSpecificOutput"])
        self.assertNotIn("permissionDecision", reply["hookSpecificOutput"])

    def test_never_leaves_the_command_alone(self):
        self.config(wrap_bash="never")
        self.assertIsNone(self.bash("ls"))

    def test_gates_apply_in_every_mode(self):
        for mode in ("default", "bypassPermissions"):
            with self.subTest(mode=mode):
                self.assertDenied(self.pre("Bash", {"command": "cat .env"}, permission_mode=mode), "dotenv")

    def test_nothing_to_wrap(self):
        self.assertIsNone(self.bash("cd /tmp"))
        self.assertIsNone(self.bash("sleep 1 &"))
        self.assertIsNone(self.bash(""))


class OtherTools(HookCase):
    def test_they_pass_straight_through(self):
        for tool in ("Grep", "Glob", "Edit", "Write", "WebFetch"):
            with self.subTest(tool=tool):
                self.assertIsNone(self.pre(tool, {"file_path": ".env", "pattern": "x"}))


class FailOpen(HookCase):
    def assertSilent(self, event, payload):
        result = run_hook(event, payload, self.home)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_bad_input_is_ignored(self):
        for event in ("pre", "post"):
            for payload in ("", "{ not json", "[]", "null", "42"):
                with self.subTest(event=event, payload=payload):
                    self.assertSilent(event, payload)

    def test_strange_fields_are_ignored(self):
        self.assertSilent("pre", {"tool_name": "Read", "tool_input": "oops"})
        self.assertSilent("pre", {"tool_name": "Bash", "tool_input": ["oops"]})
        self.assertSilent("pre", {"tool_name": "Bash", "tool_input": {"command": 42}})
        self.assertSilent("pre", {"tool_name": "Read", "tool_input": {"file_path": 42}})
        self.assertSilent("post", {"tool_name": "Bash", "tool_response": 42})

    def test_unknown_event_or_agent(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "cat .env"}})
        for args in (["nope"], [], ["pre", "--agent", "nope"], ["pre", "--agent"]):
            with self.subTest(args=args):
                result = run_module(["hushhook.hook"] + args, self.home, payload)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))

    def test_broken_config_still_gates(self):
        self.write(".config/hushhook/config.json", "{ not json")
        self.assertDenied(self.pre("Bash", {"command": "cat .env"}), "dotenv")

    def test_broken_extra_rules_still_gate(self):
        rules = self.write("mine/commands/bad.rules", "id: bad\npattern: (\nreason: x\nmatches: x\n")
        self.config(extra_rule_dirs=[os.path.dirname(os.path.dirname(rules))])
        self.assertDenied(self.pre("Bash", {"command": "cat .env"}), "dotenv")


class PostScan(HookCase):
    def log_lines(self):
        path = os.path.join(self.home, ".local", "state", "hushhook", "leaks.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle]

    def bash_response(self, text):
        return {"stdout": text, "stderr": "", "interrupted": False, "isImage": False}

    def test_a_secret_is_reported_and_masked(self):
        reply = self.post("Bash", self.bash_response("key %s\n" % TOKEN))
        self.assertIn("github-classic-token", reply["systemMessage"])
        self.assertNotIn(TOKEN, json.dumps(reply))
        output = reply["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PostToolUse")
        self.assertEqual(
            output["updatedToolOutput"],
            self.bash_response("key [hushhook:github-classic-token]\n"),
        )

    def test_nested_output_keeps_its_shape(self):
        response = {"type": "text", "file": {"filePath": "/x/a.txt", "content": TOKEN + "\n", "numLines": 1}}
        output = self.post("Read", response)["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(output["file"]["content"], "[hushhook:github-classic-token]\n")
        self.assertEqual(output["file"]["numLines"], 1)
        self.assertEqual(sorted(output), sorted(response))

    def test_plain_text_output(self):
        output = self.post("mcp__demo__tool", "value %s" % TOKEN)["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(output, "value [hushhook:github-classic-token]")

    def test_the_log_never_holds_the_value(self):
        self.post("Read", {"content": "%s and %s" % (TOKEN, TOKEN)})
        records = self.log_lines()
        self.assertEqual(len(records), 1)
        self.assertEqual(sorted(records[0]), ["count", "rule", "time", "tool"])
        self.assertEqual(records[0]["tool"], "Read")
        self.assertEqual(records[0]["rule"], "github-classic-token")
        self.assertEqual(records[0]["count"], 2)
        path = os.path.join(self.home, ".local", "state", "hushhook", "leaks.jsonl")
        with open(path, encoding="utf-8") as handle:
            self.assertNotIn(TOKEN, handle.read())
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_clean_output_says_nothing(self):
        self.assertIsNone(self.post("Bash", self.bash_response("all good\n")))
        self.assertEqual(self.log_lines(), [])

    def test_output_the_mask_already_handled_says_nothing(self):
        self.assertIsNone(self.post("Bash", self.bash_response("password=[hushhook:jwt]\n")))

    def test_an_unwritable_log_still_warns(self):
        self.write(".local/state", "not a folder")
        reply = self.post("Bash", self.bash_response(TOKEN))
        self.assertIn("github-classic-token", reply["systemMessage"])

    def test_disabled_rules_stay_quiet(self):
        self.config(disabled=["github-classic-token"])
        self.assertIsNone(self.post("Bash", self.bash_response(TOKEN)))


if __name__ == "__main__":
    unittest.main()
