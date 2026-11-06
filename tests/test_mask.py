import hashlib
import io
import os
import select
import subprocess
import sys
import tempfile
import unittest

from support import clean_env
from hushhook.mask import LINE_CAP, mask_text, stream
from hushhook.rules import expand, load_rules

SECRETS = load_rules({}, kinds=("secrets",)).secrets
TOKEN = expand("ghp_{a*36}")
SHA1 = hashlib.sha1(b"demo").hexdigest()
SHA256 = hashlib.sha256(b"demo").hexdigest()
MD5 = hashlib.md5(b"demo").hexdigest()

# Everyday output that must come through untouched.
COMMON_TEXT = [
    "total 48",
    "drwxr-xr-x  2 user staff 4096 Jan  1 00:00 src",
    "On branch main",
    "nothing to commit, working tree clean",
    "commit " + SHA1,
    "Author: Example Person <person@example.com>",
    "image: registry.example.com/app@sha256:" + SHA256,
    "checksum " + MD5,
    "uuid 123e4567-e89b-12d3-a456-426614174000",
    "https://example.com:8443/path?q=1&r=2",
    "git@github.com:example/project.git",
    "ssh://git@example.com:22/project.git",
    "postgres://localhost:5432/app",
    "postgres://app:${DB_PASSWORD}@db.example.com/app",
    "password = os.environ['DB_PASSWORD']",
    "api_key: ${{ secrets.API_KEY }}",
    "token: string;",
    "secret_key_base: <%= ENV['SECRET_KEY_BASE'] %>",
    "Authorization: Bearer $TOKEN",
    "Authorization: Bearer <token>",
    "sk-learn is a handy nickname",
    "task-runner-1234567890-abcdefghijklmnopqrstuvwxyz",
    "risk-assessment-report-2026-final-version-reviewed",
    "import numpy as np",
    "def main(argv=None):",
    "Mock.method.name",
    "foo.bar.baz.qux",
    "192.168.0.1:8080",
    "2026-11-06T12:00:00+08:00",
    "version 1.2.3-beta.4+build.5",
    ".container-fluid { margin: 0 auto; }",
    '{"id": 12345678, "name": "demo"}',
    "aGVsbG8gd29ybGQ=",
    "AKIA is the prefix of an access key id",
    "private_key_id is a field name",
    "hf_hub_download(repo_id='x')",
    "npm_config_registry=https://registry.npmjs.org/",
    "pypi-token-here",
    "ghp_short",
    "glpat-short",
    "SG.example",
    "key-value store",
    "xoxo",
    expand('BEGIN = "{-*5}BEGIN PRIVATE KEY{-*5}"'),
    expand("{-*5}BEGIN PUBLIC KEY{-*5}"),
    expand("{-*5}BEGIN CERTIFICATE{-*5}"),
    "\u6e2c\u8a66\u4e2d\u6587 and caf\u00e9 stay as they are",
]


def run_mask(data, home):
    return subprocess.run(
        [sys.executable, "-m", "hushhook.mask"], input=data, capture_output=True, env=clean_env(home), timeout=60
    )


class MaskText(unittest.TestCase):
    def test_token_becomes_its_marker(self):
        self.assertEqual(
            mask_text("key=%s done\n" % TOKEN, SECRETS),
            "key=[hushhook:github-classic-token] done\n",
        )

    def test_every_token_on_a_line_is_masked(self):
        masked = mask_text("%s %s\n" % (TOKEN, TOKEN), SECRETS)
        self.assertNotIn(TOKEN, masked)
        self.assertEqual(masked.count("[hushhook:github-classic-token]"), 2)

    def test_only_the_password_goes_from_a_url(self):
        secret = expand("{x*12}")
        masked = mask_text("postgres://app:%s@db.example.com/app\n" % secret, SECRETS)
        self.assertEqual(masked, "postgres://app:[hushhook:database-url-password]@db.example.com/app\n")

    def test_common_text_is_left_alone(self):
        for line in COMMON_TEXT:
            with self.subTest(line=line):
                self.assertEqual(mask_text(line + "\n", SECRETS), line + "\n")

    def test_line_endings_are_kept(self):
        self.assertEqual(mask_text("a\r\nb\nc", SECRETS), "a\r\nb\nc")


class MultiLineKeys(unittest.TestCase):
    def key(self, kind="RSA "):
        return expand(
            "{-*5}BEGIN %sPRIVATE KEY{-*5}\n{a*64}\n{b*64}\n{c*20}==\n{-*5}END %sPRIVATE KEY{-*5}\n" % (kind, kind)
        )

    def test_key_body_is_removed(self):
        masked = mask_text("before\n" + self.key() + "after\n", SECRETS)
        self.assertEqual(
            masked,
            "before\n[hushhook:pem-private-key]\n" + expand("{-*5}END RSA PRIVATE KEY{-*5}") + "\nafter\n",
        )

    def test_encrypted_key_headers_are_removed(self):
        text = expand(
            "{-*5}BEGIN RSA PRIVATE KEY{-*5}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,{A*32}\n\n{a*64}\n"
            "{-*5}END RSA PRIVATE KEY{-*5}\n"
        )
        masked = mask_text(text, SECRETS)
        self.assertNotIn(expand("{a*64}"), masked)
        self.assertNotIn("DEK-Info", masked)

    def test_key_on_one_line_is_masked_whole(self):
        text = expand('"private_key": "{-*5}BEGIN PRIVATE KEY{-*5}\\n{a*64}\\n{-*5}END PRIVATE KEY{-*5}\\n",\n')
        masked = mask_text(text, SECRETS)
        self.assertNotIn(expand("{a*64}"), masked)
        self.assertIn("[hushhook:pem-private-key-inline]", masked)

    def test_a_header_inside_code_keeps_the_next_lines(self):
        text = expand('BEGIN = "{-*5}BEGIN PRIVATE KEY{-*5}"\nword\n')
        self.assertEqual(mask_text(text, SECRETS), text)


class Stream(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.home = self.folder.name

    def test_output_arrives_before_input_ends(self):
        process = subprocess.Popen(
            [sys.executable, "-m", "hushhook.mask"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            env=clean_env(self.home),
        )
        try:
            process.stdin.write(b"first line\n")
            process.stdin.flush()
            ready, _, _ = select.select([process.stdout], [], [], 20)
            self.assertTrue(ready, "the mask held on to a finished line")
            self.assertEqual(process.stdout.readline(), b"first line\n")
            process.stdin.write((TOKEN + "\n").encode())
            process.stdin.flush()
            ready, _, _ = select.select([process.stdout], [], [], 20)
            self.assertTrue(ready)
            self.assertEqual(process.stdout.readline(), b"[hushhook:github-classic-token]\n")
        finally:
            process.stdin.close()
            process.stdout.close()
            self.assertEqual(process.wait(timeout=20), 0)

    def test_binary_bytes_pass_through_exactly(self):
        data = bytes(range(256)) * 4 + b"\n\xff\xfe\n"
        result = run_mask(data, self.home)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, data)

    def test_binary_lines_still_get_masked(self):
        result = run_mask(b"\xff\xfe " + TOKEN.encode() + b" \xff\n", self.home)
        self.assertEqual(result.stdout, b"\xff\xfe [hushhook:github-classic-token] \xff\n")

    def test_common_text_through_the_real_command(self):
        data = ("\n".join(COMMON_TEXT) + "\n").encode()
        self.assertEqual(run_mask(data, self.home).stdout, data)

    def test_a_secret_on_the_seam_of_a_huge_line(self):
        head = b"x" * (LINE_CAP - 10) + b" "
        data = head + TOKEN.encode() + b" " + b"y" * 1000
        sink = io.BytesIO()
        stream(io.BytesIO(data), sink, SECRETS)
        self.assertNotIn(TOKEN.encode(), sink.getvalue())
        self.assertIn(b"[hushhook:github-classic-token]", sink.getvalue())
        self.assertEqual(sink.getvalue().count(b"x"), LINE_CAP - 10)

    def test_broken_config_still_masks(self):
        folder = os.path.join(self.home, ".config", "hushhook")
        os.makedirs(folder)
        with open(os.path.join(folder, "config.json"), "w", encoding="utf-8") as handle:
            handle.write("{ not json")
        result = run_mask((TOKEN + "\n").encode(), self.home)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"[hushhook:github-classic-token]\n")


if __name__ == "__main__":
    unittest.main()
