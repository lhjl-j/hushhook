"""Claude Code adapter: hook JSON in, hook JSON out."""

from .. import gate, scan
from ..config import load_config
from ..rules import load_rules


def handle(event, payload):
    return _pre(payload) if event == "pre" else _post(payload)


def _pre(payload):
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input") or {}
    if tool not in ("Read", "Bash"):
        return None
    ctx = gate.Context()
    if tool == "Read":
        verdict = gate.check_read(tool_input.get("file_path"), tool_input.get("limit"), ctx)
    else:
        verdict = gate.check_shell(tool_input.get("command"), payload.get("cwd"), ctx)
    if verdict.action == "deny":
        return _deny(verdict.reason)
    if verdict.action == "rewrite":
        return _rewrite(tool_input, verdict.command, payload.get("permission_mode"), ctx.config.get("wrap_bash"))
    return None


def _deny(reason):
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _rewrite(tool_input, command, mode, setting):
    """Rewrite a Bash call without changing who gets asked for permission.

    Claude Code checks permission rules against the rewritten command, so in a
    mode that prompts, every allow-listed command would start prompting. "auto"
    therefore rewrites only where nothing prompts, and elsewhere leaves the
    masking to _post. Answering "allow" here would approve the command for the
    user, so it is only sent when permission checks are already off.
    """
    if setting == "never" or (setting == "auto" and mode not in (None, "bypassPermissions")):
        return None
    updated = dict(tool_input)
    updated["command"] = command
    output = {"hookEventName": "PreToolUse", "updatedInput": updated}
    if mode == "bypassPermissions":
        output["permissionDecision"] = "allow"
        output["permissionDecisionReason"] = "hushhook: output goes through the local mask"
    return {"hookSpecificOutput": output}


def _post(payload):
    response = payload.get("tool_response")
    tool = payload.get("tool_name") or "unknown"
    rules = load_rules(load_config(), kinds=("secrets",)).secrets
    counts = scan.find(response, rules)
    if not counts:
        return None
    try:
        scan.record(tool, counts)
    except OSError:
        pass
    named = ", ".join("%s x%d" % item for item in sorted(counts.items())[:3])
    return {
        "systemMessage": (
            "hushhook: %s output held a possible secret (%s). It is masked where Claude Code "
            "supports replacing tool output. If it is real, rotate it." % (tool, named)
        ),
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": scan.mask_value(response, rules),
        },
    }
