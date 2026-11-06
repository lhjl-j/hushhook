"""Settings live in one small JSON file, and every key is optional."""

import json
import os

DEFAULTS = {
    "max_read_lines": 300,
    "disabled": [],
    "extra_rule_dirs": [],
    "wrap_bash": "auto",
}
WRAP_MODES = ("auto", "always", "never")


def config_path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "hushhook", "config.json")


def state_dir():
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "hushhook")


def _read(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}, []
    except (OSError, ValueError) as exc:
        return {}, ["%s: %s" % (path, exc)]
    if not isinstance(data, dict):
        return {}, ["%s: expected a JSON object" % path]
    return data, []


def _validated(path):
    data, problems = _read(path or config_path())
    config = {key: list(value) if isinstance(value, list) else value for key, value in DEFAULTS.items()}

    limit = data.get("max_read_lines", config["max_read_lines"])
    if isinstance(limit, int) and not isinstance(limit, bool) and limit > 0:
        config["max_read_lines"] = limit
    else:
        problems.append("max_read_lines must be a positive whole number")

    for key in ("disabled", "extra_rule_dirs"):
        value = data.get(key, [])
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            config[key] = list(value)
        else:
            problems.append("%s must be a list of strings" % key)

    wrap = data.get("wrap_bash", config["wrap_bash"])
    if wrap in WRAP_MODES:
        config["wrap_bash"] = wrap
    else:
        problems.append("wrap_bash must be one of: %s" % ", ".join(WRAP_MODES))

    for key in sorted(set(data) - set(DEFAULTS)):
        problems.append("unknown setting: %s" % key)
    return config, problems


def load_config(path=None):
    """Return the settings. A bad value falls back to its default, so a typo never stops the agent."""
    return _validated(path)[0]


def check_config(path=None):
    """Return a list of problems with the config file, for `hushhook doctor`."""
    return _validated(path)[1]
