"""Claude Code PreToolUse hook: govern what the agent is about to do, within a deadline.

Installed as ``governance-gateway-hook``; the governance-guard plugin ships the same file.

Claude Code runs this before every Bash command, file write or edit, notebook edit
and web fetch, and before other MCP tools that send, post, create or write (where data
leaves), with the tool call as JSON on stdin. The text the action would send or
store goes to the governance gateway (the plugin's MCP server, on 127.0.0.1), which
always runs the personal-data check and runs the safety classifier only if it fits in
the remaining budget (GSL_HOOK_DEADLINE_MS, default 200 ms).

    harmful or malformed  -> deny: the action does not run and Claude is told why
    personal data found   -> ask: the user decides whether the action may run
    otherwise             -> no output: normal permissions apply

If the gateway (``governance-gateway``) is not running, the personal-data check still runs
here: the mandatory check is never skipped. If the hook cannot run the check at all, it blocks the action
(fail closed), unless GSL_FAIL_OPEN=1; the plugin also sets ``onFailure: "block"`` so a
hook that times out blocks too. Only the standard library is used on the normal path, so
the hook starts quickly.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

PORT = int(os.environ.get("GSL_GATEWAY_PORT", "8737"))
BUDGET_MS = float(os.environ.get("GSL_HOOK_DEADLINE_MS", "200"))
ALLOWED_DOMAINS = tuple(
    d.strip().lower()
    for d in os.environ.get("GSL_ALLOW_EMAIL_DOMAINS",
                            "anthropic.com,users.noreply.github.com,example.com").split(",")
    if d.strip())
CHUNK = 4000  # the gateway's format check accepts at most 4,000 characters
MAX_TEXT = 200_000  # beyond this an action is checked on its first 200,000 characters
FAIL_OPEN = os.environ.get("GSL_FAIL_OPEN") == "1"
EMAIL = re.compile(r"[^@\s]+@([^@\s]+\.[A-Za-z]{2,})")


def action_text(tool: str, inp: dict) -> str:
    """The text an action would run, send or store."""
    if tool == "Bash":
        return str(inp.get("command", ""))
    if tool == "Write":
        return str(inp.get("content", ""))
    if tool == "Edit":
        return str(inp.get("new_string", ""))
    if tool == "MultiEdit":
        return "\n".join(str(e.get("new_string", "")) for e in inp.get("edits", []))
    if tool == "NotebookEdit":
        return str(inp.get("new_source", ""))
    if tool == "WebFetch":
        return f"{inp.get('url', '')}\n{inp.get('prompt', '')}"
    if tool.startswith("mcp__"):  # another server's tool: every string argument
        return "\n".join(_strings(inp))
    return ""


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def without_allowed_addresses(text: str) -> str:
    """Hide no-reply and example addresses (commit trailers, documentation)."""
    def keep(m: re.Match) -> str:
        domain = m.group(1).lower()
        allowed = any(domain == d or domain.endswith("." + d) for d in ALLOWED_DOMAINS)
        return "[allowed address]" if allowed else m.group(0)
    return EMAIL.sub(keep, text)


def chunks(text: str) -> list[str]:
    """Pieces of at most CHUNK characters, split at line ends where possible."""
    out, rest = [], text
    while len(rest) > CHUNK:
        cut = rest.rfind("\n", 0, CHUNK)
        cut = cut + 1 if cut > 0 else CHUNK
        out.append(rest[:cut])
        rest = rest[cut:]
    out.append(rest)
    return [c for c in out if c.strip()]


def ask_gateway(text: str, deadline_ms: float) -> dict | None:
    body = json.dumps({"text": text, "deadline_ms": deadline_ms, "source": "hook"}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/check", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError):
        return None


# The patterns of governance_gateway.checks, repeated so the hook runs with the standard
# library alone (a test keeps the two identical).
_PII = (("e-mail address", re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")),
        ("national ID", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
        ("telephone number", re.compile(r"\+?(?:\d[\s\-().x]*){7,}")))


def local_check(text: str) -> dict:
    """Personal-data check only (the gateway is not running): the mandatory check still runs."""
    found = [kind for kind, pattern in _PII if pattern.search(text)]
    return {"verdict": "redact" if found else "allow", "pii_found": found,
            "reasons": ["gateway not running: personal-data check only"]}


def decide(payload: dict) -> dict | None:
    """The hook's JSON output for one tool call, or None to let it through."""
    text = action_text(payload.get("tool_name", ""), payload.get("tool_input") or {})
    pieces = chunks(without_allowed_addresses(text[:MAX_TEXT]))
    if not pieces:
        return None
    t0 = time.monotonic()
    verdicts = []
    for piece in pieces:
        left = BUDGET_MS - (time.monotonic() - t0) * 1e3
        verdicts.append(ask_gateway(piece, max(left, 1.0)) or local_check(piece))
    blocked = [r for v in verdicts if v["verdict"] == "block" for r in v["reasons"]]
    if blocked:
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "Governance gateway blocked this action: "
                                        + "; ".join(dict.fromkeys(blocked))}}
    found = sorted({k for v in verdicts for k in v.get("pii_found", [])})
    if found:
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "ask",
            "permissionDecisionReason": "Governance gateway: this action contains personal "
                                        f"data ({', '.join(found)}). Approve only if sharing "
                                        "or storing it is intended."}}
    return None


def main() -> int:
    try:
        out = decide(json.load(sys.stdin))
    except Exception as exc:  # noqa: BLE001 - the mandatory check could not run
        if FAIL_OPEN:
            print(f"governance-guard: check failed, allowed (GSL_FAIL_OPEN=1): {exc}",
                  file=sys.stderr)
            return 0
        print(f"governance-guard: the mandatory personal-data check could not run ({exc}); "
              "action blocked. Set GSL_FAIL_OPEN=1 to allow actions when the check fails.",
              file=sys.stderr)
        return 2
    if out is not None:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
