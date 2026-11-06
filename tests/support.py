"""Shared helpers. Anything that could touch a home folder gets a temporary one."""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def clean_env(home):
    """An environment that points every setting and log at a temporary home."""
    env = dict(os.environ)
    for name in ("XDG_CONFIG_HOME", "XDG_STATE_HOME", "CLAUDE_CONFIG_DIR"):
        env.pop(name, None)
    env["HOME"] = home
    env["PYTHONPATH"] = ROOT
    return env


def run_module(args, home, stdin="", cwd=None, env=None):
    return subprocess.run(
        [sys.executable, "-m"] + list(args),
        input=stdin,
        capture_output=True,
        text=True,
        env=env or clean_env(home),
        cwd=cwd or home,
        timeout=60,
    )


def run_hook(event, payload, home):
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    return run_module(["hushhook.hook", event], home, raw)


def answer(result):
    return json.loads(result.stdout) if result.stdout.strip() else None
