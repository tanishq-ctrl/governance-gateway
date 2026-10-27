# governance-gateway

<!-- mcp-name: io.github.tanishq-ctrl/governance-gateway -->

Governance checks that an AI agent runs before it acts, built so they keep up with the
agent instead of falling behind it.

Every request gets a format check and a personal-data (PII) scan, which never skip. A
safety classifier, which flags toxic text and jailbreak attempts, is the slow, optional
check: it runs only if a cheap screen finds the text suspicious **and** it can still
finish before the request's deadline. Under load, a guardrail that checks everything
falls behind and its checks finish after the agent has already acted; this one stays on
time and never drops the privacy check.

It runs locally as an [MCP](https://modelcontextprotocol.io) server, so text never leaves
your machine, and works with any MCP client: Claude Desktop, Claude Code, Cursor,
VS Code, Gemini CLI and others. In Claude Code an optional hook makes the checks
compulsory for every command, file write and web request the agent makes.

## Install

With [uv](https://docs.astral.sh/uv/) nothing needs installing in advance:

```bash
uvx governance-gateway --version
```

Or with pip: `pip install governance-gateway`, then run `governance-gateway`.
Python 3.10 or later; the only dependency is the `mcp` package.

## Add it to your AI tool

**Claude Desktop**: in `claude_desktop_config.json` (Settings > Developer > Edit Config):

```json
{
  "mcpServers": {
    "governance-gateway": { "command": "uvx", "args": ["governance-gateway"] }
  }
}
```

**Cursor**: the same block in `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project).

**Gemini CLI**: the same block in `~/.gemini/settings.json`.

**VS Code** (Copilot agent mode): in `.vscode/mcp.json`:

```json
{
  "servers": {
    "governance-gateway": { "type": "stdio", "command": "uvx", "args": ["governance-gateway"] }
  }
}
```

**Claude Code**:

```bash
claude mcp add governance-gateway -- uvx governance-gateway
```

If you installed with pip, use `"command": "governance-gateway"` and no `args`.

## Tools

| Tool | What it does |
|---|---|
| `check_message(text, deadline_ms=100)` | Runs the checks. Returns `allow`, `redact` (with the personal data masked) or `block`, the reasons, whether the screen and the classifier ran, and the timing. Never echoes the text back. |
| `governance_status()` | Requests so far: verdicts, mean and 95th-percentile lag, share on time, share of classifier checks skipped or screened out. |
| `recent_decisions(limit=20)` | The latest decisions: verdict, kinds of personal data found, timing. No text. |
| `decision_matrix(...)` | For a pipeline's deadline, traffic shape, peak-hour factor, detector recall, target and cost share: whether checking everything is enough, adaptive checking is needed, or only more capacity helps. |
| `simulate_load(load, deadline_ms, traffic, seconds)` | Races "check everything" against the deadline-aware guard on a simulated clock with measured check costs. |

Resources: `governance://status` and `governance://policy` (which checks run, which are
mandatory, and how the gateway decides). All tools are read-only.

## Make the checks compulsory in Claude Code

An MCP tool is only called when the agent decides to call it. In Claude Code a
`PreToolUse` hook can run the check before every action instead. The easiest way is the
`governance-guard` plugin, which adds both the server and the hook:

```
/plugin marketplace add tanishq-ctrl/governance-gateway
/plugin install governance-guard@governance-gateway
```

Or add the hook yourself to `~/.claude/settings.json` (or a project's
`.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "uvx",
            "args": ["--from", "governance-gateway", "governance-gateway-hook"],
            "timeout": 10,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

The hook sends the text of each action (the command, the file content, the URL) to the
running gateway, with a budget of `GSL_HOOK_DEADLINE_MS` (default 200 ms):

- harmful or malformed: the action is refused and the agent is told why;
- personal data found: you are asked whether to allow it;
- otherwise: nothing changes, and your normal permissions apply.

If the gateway is not running, the hook still runs the personal-data scan itself. If the
check cannot run at all, the action is blocked (set `GSL_FAIL_OPEN=1` to allow it
instead). Addresses at `GSL_ALLOW_EMAIL_DOMAINS` (default `anthropic.com,
users.noreply.github.com, example.com`) are ignored, so commit trailers pass.

## Settings

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `--cascade on/off` | `GSL_CASCADE` | `on` | Run the suspicion screen before the classifier |
| `--estimator p90/mean` | `GSL_ESTIMATOR` | `p90` | How the classifier's cost is estimated from recent checks |
| `--workers N` | `GSL_GATEWAY_WORKERS` | 1 | Workers serving the queue |
| `--audit-log PATH` | `GSL_AUDIT_LOG` | none | Append one JSON line per decision (no text) |
| `--port N` | `GSL_GATEWAY_PORT` | 8737 | Local port for the hook (127.0.0.1 only) |
| `--no-hook-endpoint` | | | Do not open the local port |

## What it detects, and what it does not

- **Personal data**: e-mail addresses, telephone numbers and US-style national ID
  numbers, by pattern. Names, postal addresses and other identifiers are **not** detected.
- **Harmful text**: a TF-IDF and logistic-regression classifier trained on ToxicChat, real
  prompts to a public chatbot labelled by people. On held-out ToxicChat messages it
  catches about 6 in 10 harmful messages with a precision of about 0.78; it is a light
  first line of defence, not a complete safety system, and it was trained on English.
- **The screen** passes on 95% of harmful messages in validation and sends about 31% of
  ordinary traffic to the classifier.

Use it alongside, not instead of, your organisation's own data-protection controls.

## Background

The gateway comes from an MSc project that measured how far governance checks fall
behind fast automated decisions as load grows. Checking everything collapses at full
capacity: on real chatbot traffic it stopped meeting its target at 77% of capacity. The
deadline rule held to 1.06, and the screen plus the deadline rule to 1.44, while keeping
the privacy check on time.

Prabhu, T. S. (2026). *Quantifying "Governance Speed Lag" (GSL) in Agentic AI
Ecosystems: A simulation-based framework for self-adaptive real-time data compliance.*
MSc Data Science project, VIT.

## Source and issues

https://github.com/tanishq-ctrl/governance-gateway

## Licence

Code: MIT. The bundled models and workload data are derived from ToxicChat and are for
**non-commercial use only** (CC BY-NC 4.0); see [LICENSE-DATA.md](https://github.com/tanishq-ctrl/governance-gateway/blob/main/LICENSE-DATA.md).
