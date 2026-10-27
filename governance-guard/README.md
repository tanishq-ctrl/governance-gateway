# governance-guard

A Claude Code plugin that puts the project's deadline-aware guardrail in front of an AI
agent. It has two parts.

**MCP server** (`gateway`), tools the agent can call:

| Tool | What it does |
|---|---|
| `check_message(text, deadline_ms=100)` | Format check and personal-data scan (always), safety classifier (only if it fits before the deadline). Returns `allow`, `redact` (with the redacted text) or `block`, the reasons, and the timing. Never echoes the text back. |
| `governance_status()` | Requests so far: verdicts, mean and p95 lag, share on time, share of classifier checks skipped. |
| `decision_matrix(...)` | Which checking policy a pipeline needs at a given load (report Section 4.14). |
| `simulate_load(load, deadline_ms, traffic, seconds)` | Races "check everything" against the deadline-aware guard with the guardrail's measured costs. |
| `recent_decisions(limit=20)` | The latest decisions: source, verdict, kinds of personal data, whether the classifier ran, timing. No text. |

Resources: `governance://status` and `governance://policy` (the checks, which are mandatory, the default
deadline and the cost estimator). All tools are marked read-only.

**PreToolUse hook**: before every `Bash` command, file `Write`/`Edit`/`MultiEdit`,
`NotebookEdit` and `WebFetch`, and before other servers' MCP tools that send, post, create,
write, update, upload, share, publish, reply, draft, insert, append, edit or submit, the text the action would run, send or store goes to the
same gateway, with a budget of `GSL_HOOK_DEADLINE_MS` (default 200 ms):

- harmful or malformed: **deny** (the action does not run; Claude is told why);
- personal data found: **ask** (you decide);
- otherwise: no output, so the normal permission rules apply.

If the gateway is not running, the hook still runs the personal-data check itself: the
mandatory check is never skipped. If the check cannot run at all, the action is blocked
(fail closed; `GSL_FAIL_OPEN=1` to allow instead), and the hooks set `onFailure: "block"`
so a hook that times out blocks too (Claude Code 2.1.295 or later). No-reply and example addresses
(`GSL_ALLOW_EMAIL_DOMAINS`, default `anthropic.com,users.noreply.github.com,example.com`)
are ignored, so commit trailers do not trigger it.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `GSL_HOOK_DEADLINE_MS` | 200 | Budget for checking one action |
| `GSL_GATEWAY_WORKERS` | 1 | Workers serving the gateway's queue |
| `GSL_ESTIMATOR` | `p90` | Classifier cost estimate: 90th percentile of recent costs (cautious) or `mean` |
| `GSL_AUDIT_LOG` | plugin data folder | JSON-lines audit log of decisions (no text) |
| `GSL_FAIL_OPEN` | unset | `1` lets actions through when the check cannot run |
| `GSL_ALLOW_EMAIL_DOMAINS` | anthropic.com, users.noreply.github.com, example.com | Addresses ignored by the hook |

## Requirements

The server is the `governance-gateway` package (packages/governance-gateway). Inside the
thesis repository the plugin runs it from source with the repository's `.venv`; anywhere
else it runs the published package with `uvx governance-gateway` (install
[uv](https://docs.astral.sh/uv/)), or a checkout named by `GSL_REPO`. The hook
(`hooks/guard.py`, the package's `governance_gateway/hook.py`) needs only Python 3.

## Use it

Install from GitHub, in Claude Code:

```
/plugin marketplace add tanishq-ctrl/governance-gateway
/plugin install governance-guard@governance-gateway
```

or from a terminal: `claude plugin marketplace add tanishq-ctrl/governance-gateway`, then
`claude plugin install governance-guard@governance-gateway`. The plugin starts the server
with `uvx governance-gateway`, so [uv](https://docs.astral.sh/uv/) must be installed.

To try a local checkout for one session: `claude --plugin-dir ./governance-guard` (in the
public repository) or `claude --plugin-dir ./agent/governance-guard` (in the thesis
repository).

Check that it loaded: `claude plugin list` and `claude mcp list`
(`plugin:governance-guard:gateway … Connected`). The gateway also answers on
`http://127.0.0.1:8737/status` (port `GSL_GATEWAY_PORT`) while a session is open.
