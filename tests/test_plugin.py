"""The Claude Code plugin: its hooks, and its copy of the package's hook."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "governance-guard"
HOOK = PLUGIN / "hooks" / "guard.py"


def test_the_plugin_ships_the_packages_hook_unchanged():
    assert HOOK.read_text() == (ROOT / "src" / "governance_gateway" / "hook.py").read_text()


def test_hooks_fail_closed_and_skip_the_plugins_own_tools():
    spec = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]["PreToolUse"]
    assert all(h["onFailure"] == "block" for entry in spec for h in entry["hooks"])
    mcp = re.compile(spec[1]["matcher"])
    assert mcp.search("mcp__claude_ai_Gmail__create_draft")
    assert not mcp.search("mcp__plugin_governance-guard_gateway__check_message")
    assert not mcp.search("mcp__claude_ai_Gmail__search_threads")


def test_the_marketplace_lists_the_plugin():
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    (entry,) = market["plugins"]
    assert entry["name"] == "governance-guard" and (ROOT / entry["source"]).is_dir()
