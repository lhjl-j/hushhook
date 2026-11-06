import os
import tempfile
import time
import unittest

import support  # noqa: F401
from hushhook.config import load_config
from hushhook.rules import MARKER, check_rule, expand, load_rules, parse_text, required_text


class BuiltInRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules({}, include_disabled=True)

    def test_packs_load_cleanly(self):
        self.assertEqual(self.rules.errors, [])

    def test_every_example_behaves(self):
        for rule in self.rules.all():
            with self.subTest(rule=rule.id):
                self.assertEqual(check_rule(rule), [])

    def test_every_rule_shows_both_sides(self):
        for rule in self.rules.all():
            with self.subTest(rule=rule.id):
                self.assertTrue(rule.matches, "needs a matches: line")
                self.assertTrue(rule.ignores, "needs an ignores: line")

    def test_ids_are_unique_across_kinds(self):
        ids = [rule.id for rule in self.rules.all()]
        self.assertEqual(sorted(ids), sorted(set(ids)))

    def test_enough_rules_ship(self):
        self.assertGreaterEqual(len(self.rules.secrets), 25)
        self.assertGreaterEqual(len(self.rules.files), 15)
        self.assertGreaterEqual(len(self.rules.commands), 12)

    def test_masked_examples_show_the_rule_id(self):
        for rule in self.rules.secrets:
            for example in rule.matches:
                with self.subTest(rule=rule.id, example=example):
                    text = expand(example)
                    masked = rule.mask(text)
                    self.assertIn(MARKER % rule.id, masked)
                    self.assertNotEqual(masked, text)

    def test_required_text_is_in_every_example(self):
        for rule in self.rules.secrets:
            for example in rule.matches:
                with self.subTest(rule=rule.id, example=example):
                    text = expand(example)
                    self.assertTrue(rule.worth_trying(text, text.lower()))

    def test_most_rules_can_skip_the_regular_expression(self):
        with_hint = [rule for rule in self.rules.secrets if rule.hint]
        self.assertGreaterEqual(len(with_hint), len(self.rules.secrets) - 3)

    def test_no_pattern_stalls_on_a_long_line(self):
        samples = ["a" * 200000, "a-" * 100000, "M" * 200000, "x y " * 50000, "://" * 60000, "=" * 200000]
        for rule in self.rules.secrets + self.rules.commands:
            with self.subTest(rule=rule.id):
                started = time.monotonic()
                for sample in samples:
                    rule.regex.search(sample)
                self.assertLess(time.monotonic() - started, 2.0)


class RequiredText(unittest.TestCase):
    def test_finds_text_every_match_must_hold(self):
        cases = {
            r"\bghp_[A-Za-z0-9]{36}\b": ("ghp_", False),
            r"(?i)\bToken=[a-z]+": ("token=", True),
            r"(?m)-----BEGIN (?:RSA )?KEY-----$": ("-----BEGIN ", False),
            r"[0-9]{8}:AA[a-z]{3}": (":AA", False),
            r"[a-z]{14}\.atlasv1\.[a-z]+": (".atlasv1.", False),
            r"https?://x": ("http", False),
            r"https?://xy": ("://xy", False),
            r"abc?d": ("ab", False),
            r"ab+cd": ("ab", False),
            r"ab+cde": ("cde", False),
            r"(x|y)zz": ("zz", False),
            r"(?:[)]|z)qq": ("qq", False),
        }
        for pattern, expected in cases.items():
            with self.subTest(pattern=pattern):
                self.assertEqual(required_text(pattern), expected)

    def test_stays_quiet_when_it_cannot_be_sure(self):
        patterns = (
            r"foo|bar", r"(?x) a b", r"a?b?", r"[ab]+", r"a.b", r"(?:foo|bar)", r"(?s)abc", r"\x41bc", r"\u0041bc",
            r"(a)\1bc", r"abc{x|def}",
        )
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertEqual(required_text(pattern), ("", False))

    def test_a_rule_without_a_hint_still_runs(self):
        rules, _ = parse_text("id: x\npattern: foo|bar\nmatches: bar\n", "secrets")
        self.assertEqual(rules[0].hint, "")
        self.assertTrue(rules[0].worth_trying("bar", "bar"))
        self.assertEqual(rules[0].mask("a bar"), "a [hushhook:x]")


class RuleFormat(unittest.TestCase):
    def test_expand_repeats_text(self):
        self.assertEqual(expand("x_{a*3}{bc*2}"), "x_aaabcbc")

    def test_expand_leaves_regex_counts_alone(self):
        self.assertEqual(expand("a{2,3}"), "a{2,3}")

    def test_comments_and_blank_lines(self):
        text = "# top\n\nid: one\n# inside\npattern: a+\nmatches: aa\n\n\nid: two\npattern: b+\nmatches: bb\n"
        rules, errors = parse_text(text, "secrets")
        self.assertEqual(errors, [])
        self.assertEqual([rule.id for rule in rules], ["one", "two"])

    def test_pattern_needs_no_escaping(self):
        rules, errors = parse_text("id: one\npattern: a#b:c\\d+ \nmatches: a#b:c1\n", "secrets")
        self.assertEqual(errors, [])
        self.assertTrue(rules[0].hits("a#b:c1"))

    def test_a_bad_rule_does_not_stop_the_good_ones(self):
        text = "id: bad\npattern: (\nmatches: x\n\nid: good\npattern: a\nmatches: a\n"
        rules, errors = parse_text(text, "secrets", "demo.rules")
        self.assertEqual([rule.id for rule in rules], ["good"])
        self.assertEqual(len(errors), 1)
        self.assertIn("demo.rules:1", errors[0])

    def test_problems_are_reported(self):
        cases = [
            ("id: x\npattern: a\n", "matches"),
            ("pattern: a\nmatches: a\n", "id"),
            ("id: Not_Valid\npattern: a\nmatches: a\n", "lowercase"),
            ("id: x\nregex: a\nmatches: a\n", "expected one of"),
            ("id: x\npattern: a\npattern: b\nmatches: a\n", "twice"),
        ]
        for text, expected in cases:
            with self.subTest(expected=expected):
                rules, errors = parse_text(text, "secrets")
                self.assertEqual(rules, [])
                self.assertIn(expected, errors[0])

    def test_commands_need_a_reason(self):
        _, errors = parse_text("id: x\npattern: a\nmatches: a\n", "commands")
        self.assertIn("reason", errors[0])

    def test_files_except_wins(self):
        rules, _ = parse_text("id: x\nglob: .env.*\nexcept: .env.example\nmatches: .env.local\n", "files")
        self.assertTrue(rules[0].hits("/app/.env.local"))
        self.assertFalse(rules[0].hits("/app/.env.example"))

    def test_folder_globs_match_the_end_of_the_path(self):
        rules, _ = parse_text("id: x\nglob: .aws/credentials\nmatches: .aws/credentials\n", "files")
        self.assertTrue(rules[0].hits("/root/.aws/credentials"))
        self.assertFalse(rules[0].hits("/root/credentials"))

    def test_check_rule_reports_examples_in_short_form(self):
        rules, _ = parse_text("id: x\npattern: b+\nmatches: {a*3}\nignores: {b*3}\n", "secrets")
        problems = check_rule(rules[0])
        self.assertEqual(len(problems), 2)
        self.assertIn("{a*3}", problems[0])
        self.assertIn("{b*3}", problems[1])


class Loading(unittest.TestCase):
    def test_extra_folder_adds_and_overrides(self):
        with tempfile.TemporaryDirectory() as folder:
            os.makedirs(os.path.join(folder, "secrets"))
            with open(os.path.join(folder, "secrets", "mine.rules"), "w", encoding="utf-8") as handle:
                handle.write("id: my-token\npattern: mine_[0-9]+\nmatches: mine_1\n\n")
                handle.write("id: github-classic-token\npattern: replaced\nmatches: replaced\n")
            rules = load_rules({"extra_rule_dirs": [folder]}, kinds=("secrets",))
            by_id = {rule.id: rule for rule in rules.secrets}
            self.assertEqual(rules.errors, [])
            self.assertIn("my-token", by_id)
            self.assertTrue(by_id["github-classic-token"].hits("replaced"))

    def test_disabled_rules_stay_out(self):
        rules = load_rules({"disabled": ["jwt"]}, kinds=("secrets",))
        self.assertNotIn("jwt", [rule.id for rule in rules.secrets])

    def test_defaults_when_there_is_no_config(self):
        with tempfile.TemporaryDirectory() as folder:
            config = load_config(os.path.join(folder, "missing.json"))
        self.assertEqual(config["max_read_lines"], 300)
        self.assertEqual(config["disabled"], [])


if __name__ == "__main__":
    unittest.main()
