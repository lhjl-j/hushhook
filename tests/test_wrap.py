import os
import shutil
import subprocess
import tempfile
import unittest

from support import clean_env
from hushhook.gate import mask_command
from hushhook.rules import expand
from hushhook.shell import blank_quotes, is_backgrounded, is_masked, pipelines, strip_heredocs, wrap

TOKEN = expand("ghp_{a*36}")


class Wrapping(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.home = os.path.realpath(self.folder.name)

    def run_wrapped(self, command, shell_name="bash", suffix=""):
        rewritten = wrap(command, mask_command())
        self.assertIsNotNone(rewritten)
        return subprocess.run(
            [shell_name, "-c", rewritten + suffix],
            capture_output=True,
            text=True,
            env=clean_env(self.home),
            cwd=self.home,
            timeout=60,
        )

    def test_exit_codes_are_kept(self):
        for command, code in (("true", 0), ("false", 1), ("exit 7", 7), ("(exit 3)", 3), ("sh -c 'exit 42'", 42)):
            with self.subTest(command=command):
                self.assertEqual(self.run_wrapped(command).returncode, code)

    def test_the_commands_own_pipes_behave_as_written(self):
        self.assertEqual(self.run_wrapped("false | true").returncode, 0)
        self.assertEqual(self.run_wrapped("true | false").returncode, 1)
        self.assertEqual(self.run_wrapped("yes | head -1").returncode, 0)

    @unittest.skipUnless(shutil.which("zsh"), "zsh is not installed")
    def test_exit_codes_in_zsh(self):
        self.assertEqual(self.run_wrapped("exit 7", "zsh").returncode, 7)
        self.assertEqual(self.run_wrapped("false | true", "zsh").returncode, 0)

    def test_stdout_and_stderr_are_masked(self):
        result = self.run_wrapped("echo %s; echo %s >&2" % (TOKEN, TOKEN))
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("[hushhook:github-classic-token]"), 2)

    def test_cd_stays_outside(self):
        rewritten = wrap("cd /tmp && ls", "MASK")
        self.assertTrue(rewritten.startswith("cd /tmp && set -o pipefail"))
        result = self.run_wrapped("cd /tmp && true", suffix="\npwd")
        # macOS: /tmp is a link, so compare the real locations.
        self.assertEqual(os.path.realpath(result.stdout.strip()), os.path.realpath("/tmp"))

    def test_quoted_and_repeated_cd(self):
        os.makedirs(os.path.join(self.home, "a b", "c"))
        result = self.run_wrapped('cd "a b" && cd c && true', suffix="\npwd")
        self.assertEqual(result.stdout.strip(), os.path.join(self.home, "a b", "c"))

    def test_a_failed_cd_stops_the_rest(self):
        marker = os.path.join(self.home, "ran")
        result = self.run_wrapped("cd /no/such/folder && touch %s" % marker)
        self.assertFalse(os.path.exists(marker))
        self.assertNotEqual(result.returncode, 0)

    def test_cd_then_semicolon_still_runs_the_rest(self):
        marker = os.path.join(self.home, "ran")
        self.run_wrapped("cd /no/such/folder; touch %s" % marker)
        self.assertTrue(os.path.exists(marker))

    def test_here_documents_and_trailing_comments(self):
        result = self.run_wrapped("cat <<EOF\nhello there\nEOF")
        self.assertEqual(result.stdout, "hello there\n")
        self.assertEqual(self.run_wrapped("echo ok # a note").stdout, "ok\n")

    def test_plain_cd_is_left_alone(self):
        for command in ("cd", "cd /tmp", 'cd "a b"', "cd /tmp;"):
            with self.subTest(command=command):
                self.assertIsNone(wrap(command, "MASK"))

    def test_background_commands_are_left_alone(self):
        for command in ("sleep 9 &", "sleep 9 & echo started", "nohup sleep 9", "setsid sleep 9", "a; nohup b", "(sleep 9 &)"):
            with self.subTest(command=command):
                self.assertIsNone(wrap(command, "MASK"))

    def test_lookalikes_of_background_are_wrapped(self):
        for command in ("a && b", "ls 2>&1", 'echo "a & b"', "echo a\\&b", "cmd &> out", "a |& b", "grep nohup log"):
            with self.subTest(command=command):
                self.assertIsNotNone(wrap(command, "MASK"))

    def test_wrapping_twice_changes_nothing(self):
        once = wrap("ls", mask_command())
        self.assertTrue(is_masked(once))
        self.assertIsNone(wrap(once, mask_command()))
        self.assertIsNone(wrap("ls | hushhook mask", mask_command()))

    def test_talking_about_the_mask_is_not_using_it(self):
        self.assertFalse(is_masked("grep 'hushhook mask' README.md"))
        self.assertFalse(is_masked("echo hushhook mask"))
        self.assertIsNotNone(wrap("echo hushhook mask", "MASK"))

    def test_empty_commands_are_left_alone(self):
        self.assertIsNone(wrap("", "MASK"))
        self.assertIsNone(wrap(None, "MASK"))


class Reading(unittest.TestCase):
    def verbs(self, command):
        return [[segment.command()[0] for segment in pipeline] for pipeline in pipelines(command)]

    def test_splits_pipelines_and_steps(self):
        self.assertEqual(self.verbs("a | b && c; d\ne"), [["a", "b"], ["c"], ["d"], ["e"]])

    def test_skips_assignments_and_wrappers(self):
        self.assertEqual(self.verbs("FOO=1 sudo -n cat x"), [["cat"]])

    def test_redirects(self):
        segment = pipelines("cat a > b")[0][0]
        self.assertTrue(segment.stdout_to_file)
        self.assertEqual(segment.words, ["cat", "a"])
        self.assertFalse(pipelines("cat a 2>/dev/null")[0][0].stdout_to_file)
        self.assertFalse(pipelines("cat a 2>&1")[0][0].stdout_to_file)
        self.assertEqual(pipelines("cat < a")[0][0].reads, ["a"])

    def test_substitution_is_seen(self):
        self.assertIn(["cat"], self.verbs("echo $(cat x)"))

    def test_unbalanced_quotes_give_up_quietly(self):
        self.assertEqual(pipelines("echo 'oops"), [])

    def test_here_document_bodies_are_not_commands(self):
        self.assertEqual(strip_heredocs("cat <<EOF | grep a\nb\nEOF\nc"), "cat  | grep a\nc")
        self.assertEqual(self.verbs("cat <<'EOF'\nls\nEOF"), [["cat"]])
        self.assertEqual(strip_heredocs("cat <<< word"), "cat <<< word")

    def test_blank_quotes_keeps_length(self):
        text = "echo 'a b' \"c\\\"d\" e\\&f"
        self.assertEqual(len(blank_quotes(text)), len(text))
        self.assertNotIn("&", blank_quotes(text))

    def test_background_detection_skips_here_documents(self):
        self.assertFalse(is_backgrounded("cat <<EOF\na & b\nEOF"))


if __name__ == "__main__":
    unittest.main()
