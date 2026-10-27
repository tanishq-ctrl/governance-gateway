# Changelog

## 0.1.1 (2026-10-27)

- Repository, issue and changelog links on PyPI and in the MCP Registry entry.
- README: absolute licence link (the relative link did not work on PyPI); how to install
  the Claude Code plugin from the public repository.
- Test settings in `pyproject.toml`, so the package's tests run from its own folder.

No change to the checks, the models or the tools.

## 0.1.0 (2026-10-27)

First release: MCP server with `check_message`, `governance_status`, `recent_decisions`,
`decision_matrix` and `simulate_load`; suspicion screen and deadline rule; Claude Code
hook (`governance-gateway-hook`); models as JSON scored in pure Python.
