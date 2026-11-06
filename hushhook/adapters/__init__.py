"""One small adapter per agent. The decisions stay in gate.py and scan.py.

An adapter is a module with handle(event, payload), where event is "pre" or
"post" and payload is the parsed hook JSON. It returns the JSON to print, or
None when the agent should simply carry on.
"""

import importlib

ADAPTERS = {
    "claude-code": "hushhook.adapters.claude_code",
}


def get(name):
    return importlib.import_module(ADAPTERS[name])
