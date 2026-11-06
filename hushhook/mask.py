"""Stdin to stdout, one line at a time: known secrets become [hushhook:<rule-id>].

Nothing is held back beyond the current line, so long-running commands still
stream. This module must never end a pipeline with an error of its own: if the
rules cannot be loaded, the text passes through unchanged.
"""

import os
import sys

LINE_CAP = 1 << 20  # a longer line is handled in pieces, so memory stays flat
OVERLAP = 1 << 12  # kept between pieces, so a secret on the seam still matches


class Masker:
    """Masks text line by line and remembers when it is inside a multi-line secret."""

    def __init__(self, rules):
        self.rules = rules
        self.block = None

    def line(self, text):
        """Return the masked line. Lines inside a multi-line secret come back empty."""
        if self.block is not None:
            if self.block.body.match(text.rstrip("\r\n")):
                return ""
            self.block = None
        lowered = text.lower()
        for rule in self.rules:
            if not rule.worth_trying(text, lowered):
                continue
            masked = rule.mask(text)
            if masked != text:
                text = masked
                if rule.body is not None:
                    self.block = rule
        return text


def mask_text(text, rules):
    """Mask a whole string, keeping its line endings."""
    masker = Masker(rules)
    return "".join(masker.line(line) for line in text.splitlines(True))


def _mask_bytes(masker, data):
    text = data.decode("utf-8", "surrogateescape")
    masked = masker.line(text)
    return data if masked == text else masked.encode("utf-8", "surrogateescape")


def stream(source, sink, rules):
    """Copy binary source to sink, masking each line and flushing as it goes."""
    masker = Masker(rules)
    held = b""
    while True:
        chunk = source.readline(LINE_CAP)
        if not chunk:
            break
        data = held + chunk
        held = b""
        if len(chunk) == LINE_CAP and not chunk.endswith(b"\n"):
            data, held = data[:-OVERLAP], data[-OVERLAP:]
        sink.write(_mask_bytes(masker, data))
        sink.flush()
    if held:
        sink.write(_mask_bytes(masker, held))
        sink.flush()


def load_secret_rules():
    """Return the active secrets rules, or none at all if anything goes wrong."""
    try:
        from .config import load_config
        from .rules import load_rules

        return load_rules(load_config(), kinds=("secrets",)).secrets
    except Exception:
        return []


def main():
    try:
        stream(sys.stdin.buffer, sys.stdout.buffer, load_secret_rules())
    except BrokenPipeError:
        # The reader went away (for example `hushhook mask | head -1`). Avoid a noisy exit.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main())
