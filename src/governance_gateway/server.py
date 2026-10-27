"""MCP server: the governance gateway as tools an AI agent calls before it acts.

Run with ``governance-gateway`` (or ``python -m governance_gateway``; stdio). Tools:

    check_message      run the deadline-aware guardrail on a text the agent is about to act on
    governance_status  what the gateway has done: verdicts, lag, how often it skipped
    decision_matrix    which checking policy a pipeline needs (Section 4.14, O5)
    simulate_load      race full checking against the deadline-aware guard at a chosen load
    recent_decisions   the latest decisions (verdict, kinds of personal data, timing; no text)

Resources: ``governance://status`` and ``governance://policy`` (the checks, which are
mandatory, the default deadline and how the classifier's cost is estimated).

Settings (command-line options, or the environment): GSL_GATEWAY_WORKERS (default 1),
GSL_ESTIMATOR ("p90" or "mean"), GSL_AUDIT_LOG (path of a JSON-lines audit log; no text is
written to it), GSL_CASCADE ("on": run the bundled suspicion screen first; "off").

The server also listens on 127.0.0.1 (port ``GSL_GATEWAY_PORT``, default 8737) so the
Claude Code plugin's PreToolUse hook can use the same warm model and the same queue:
``POST /check`` with ``{"text": ..., "deadline_ms": ...}`` and ``GET /status``.
Nothing is written to stdout except the MCP protocol.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from governance_gateway import __version__
from governance_gateway import gateway as gw
from governance_gateway.model import load_screen as _bundled_screen

PORT = int(os.environ.get("GSL_GATEWAY_PORT", "8737"))
MAX_BODY = 64_000
WORKERS = int(os.environ.get("GSL_GATEWAY_WORKERS", "1"))
ESTIMATOR = os.environ.get("GSL_ESTIMATOR", "p90")
AUDIT_LOG = os.environ.get("GSL_AUDIT_LOG") or None
CASCADE = os.environ.get("GSL_CASCADE", "on")


def load_screen():
    """The bundled suspicion screen, unless the cascade is off."""
    return None if CASCADE == "off" else _bundled_screen()
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)

server = MCPServer(
    "governance-speed-lag",
    instructions=(
        "Governance gateway from the Governance Speed Lag project. Call check_message on any "
        "text you are about to send, store or act on (a message, an email, a command's "
        "content). Obey the verdict: 'block' means do not proceed; 'redact' means use the "
        "returned redacted text instead. The PII check always runs; the slower safety "
        "classifier is skipped only when it would miss the deadline."),
)
_gateway: gw.Gateway | None = None
_gateway_lock = threading.Lock()


def get_gateway() -> gw.Gateway:
    """The one gateway of this process, loaded on first use."""
    global _gateway
    with _gateway_lock:
        if _gateway is None:
            _gateway = gw.Gateway(workers=WORKERS, estimator=ESTIMATOR, audit_path=AUDIT_LOG,
                                  screen=load_screen())
        return _gateway


@server.tool(annotations=READ_ONLY)
def check_message(text: str, deadline_ms: float = gw.DEFAULT_DEADLINE_MS) -> dict[str, Any]:
    """Check a text before acting on it: format, personal data (always) and safety (if time allows).

    Returns the verdict ('allow', 'redact' or 'block'), the reasons, the redacted text when
    personal data was found, whether the safety classifier ran, and the timing against the
    deadline. The original text is never echoed back.
    """
    return get_gateway().check(text, deadline_ms, source="mcp").to_dict()


@server.tool(annotations=READ_ONLY)
def governance_status() -> dict[str, Any]:
    """Requests handled so far: verdicts, lag (mean, p95), share on time, share skipped."""
    return get_gateway().status()


@server.tool(annotations=READ_ONLY)
def decision_matrix(deadline_ms: float = 100.0, traffic: str = "random",
                    peak_factor: float = 1.0, recall: float = 0.86, target: float = 0.70,
                    cost_share: float = 0.88, load: float = 0.8) -> dict[str, Any]:
    """Which checking policy a pipeline needs at a given mean load (the project's decision matrix).

    traffic: 'even', 'random' or 'bursty'. peak_factor: busiest-hour ratio q (1 = steady).
    recall: the detector's recall with no queue; target: required share caught in time;
    cost_share: the detector's share of checking cost; load: mean arrivals ÷ capacity.
    """
    return gw.decision_matrix(deadline_ms, traffic, peak_factor, recall, target, cost_share,
                              load)


@server.tool(annotations=READ_ONLY)
def simulate_load(load: float = 1.3, deadline_ms: float = 100.0, traffic: str = "steady",
                  seconds: float = 15.0, seed: int = 0) -> dict[str, Any]:
    """Race 'check everything' against the deadline-aware guard with measured check costs.

    traffic: 'steady', 'rush_hour' or 'real_chatbot' (real WildChat timings). Returns, for
    each guard, the final lag, harmful messages caught in time, the share of PII checks on
    time and the share of classifier checks skipped.
    """
    return gw.simulate_load(load, deadline_ms, traffic, seconds, seed)


@server.tool(annotations=READ_ONLY)
def recent_decisions(limit: int = 20) -> list[dict[str, Any]]:
    """The latest governance decisions, newest last: source, verdict, kinds of personal data
    found, whether the classifier ran, and timing. The checked text is never included."""
    return get_gateway().recent(limit)


def policy() -> dict[str, Any]:
    """What the gateway checks and how it decides."""
    cascade = get_gateway().screen is not None
    checks = [
        {"name": "format check", "mandatory": True,
         "rule": "non-empty text of at most 4,000 characters"},
        {"name": "PII scan (GDPR)", "mandatory": True,
         "rule": "e-mail addresses, national ID numbers and telephone numbers; redacted"},
    ]
    if cascade:
        checks.append({"name": "suspicion screen", "mandatory": True,
                       "rule": "cheap word-level classifier on every request"})
    checks.append({"name": "safety classifier", "mandatory": False,
                   "rule": "TF-IDF and logistic regression trained on ToxicChat; runs only if "
                           + ("the screen finds the text suspicious and " if cascade else "")
                           + "its estimated cost fits before the request's deadline"})
    return {
        "checks": checks,
        "cascade": cascade,
        "default_deadline_ms": gw.DEFAULT_DEADLINE_MS,
        "cost_estimator": ESTIMATOR, "workers": WORKERS,
        "verdicts": {"block": "format failed or harmful", "redact": "personal data found",
                     "allow": "nothing found"},
        "audit_log": bool(AUDIT_LOG),
    }


@server.resource("governance://status", name="status", mime_type="application/json",
                 description="Live counts, lag and skip rate of the governance gateway")
def status_resource() -> str:
    return json.dumps(get_gateway().status())


@server.resource("governance://policy", name="policy", mime_type="application/json",
                 description="The checks the gateway runs, which are mandatory, and how it decides")
def policy_resource() -> str:
    return json.dumps(policy())


class _Handler(BaseHTTPRequestHandler):
    """Local endpoint for the PreToolUse hook (127.0.0.1 only)."""

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/status":
            self._send(200, get_gateway().status())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/check":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_BODY:
                raise ValueError("request too large")
            body = json.loads(self.rfile.read(length) or b"{}")
            text = body.get("text", "")
            deadline = float(body.get("deadline_ms", gw.DEFAULT_DEADLINE_MS))
            source = str(body.get("source", "hook"))[:40]
            self._send(200, get_gateway().check(text, deadline, source=source).to_dict())
        except (ValueError, TypeError) as exc:
            self._send(400, {"error": str(exc)})

    def log_message(self, *args) -> None:  # keep stdout and stderr quiet
        pass


def start_http(port: int = PORT) -> ThreadingHTTPServer | None:
    """Serve the hook endpoint in a background thread; None if the port is taken."""
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    except OSError as exc:
        print(f"gsl gateway: hook endpoint not started on port {port}: {exc}", file=sys.stderr)
        return None
    threading.Thread(target=httpd.serve_forever, name="gsl-hook-endpoint", daemon=True).start()
    return httpd


def main(argv: list[str] | None = None) -> None:
    import argparse

    global PORT, WORKERS, ESTIMATOR, AUDIT_LOG, CASCADE
    parser = argparse.ArgumentParser(
        prog="governance-gateway",
        description="Deadline-aware governance checks for AI agents, as an MCP server (stdio).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--port", type=int, default=PORT,
                        help="local port of the hook endpoint (default %(default)s)")
    parser.add_argument("--no-hook-endpoint", action="store_true",
                        help="do not listen on 127.0.0.1 for the Claude Code hook")
    parser.add_argument("--workers", type=int, default=WORKERS)
    parser.add_argument("--estimator", choices=gw.ESTIMATORS, default=ESTIMATOR)
    parser.add_argument("--audit-log", default=AUDIT_LOG,
                        help="append one JSON line per decision (no text) to this file")
    parser.add_argument("--cascade", choices=("on", "off"), default=CASCADE)
    args = parser.parse_args(argv)
    PORT, WORKERS, ESTIMATOR = args.port, args.workers, args.estimator
    AUDIT_LOG, CASCADE = args.audit_log, args.cascade
    get_gateway()  # load the models before the first request
    if not args.no_hook_endpoint:
        start_http(PORT)
    server.run("stdio")


if __name__ == "__main__":
    main()
