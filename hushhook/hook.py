"""Hook entry point: python3 -m hushhook.hook pre|post [--agent NAME].

Whatever goes wrong in here, the agent carries on: exit 0 and nothing on stdout.
"""

import sys


def respond(argv, raw):
    """Return the text to print for one hook call, or None."""
    import json

    from . import adapters

    event = argv[0] if argv else ""
    if event not in ("pre", "post"):
        return None
    agent = argv[argv.index("--agent") + 1] if "--agent" in argv else "claude-code"
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        return None
    answer = adapters.get(agent).handle(event, payload)
    return json.dumps(answer) if answer else None


def main(argv=None):
    text = None
    try:
        if sys.version_info >= (3, 9):
            raw = sys.stdin.buffer.read().decode("utf-8", "replace")
            text = respond(list(sys.argv[1:] if argv is None else argv), raw)
    except BaseException:
        text = None
    if text:
        try:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
        except BaseException:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
