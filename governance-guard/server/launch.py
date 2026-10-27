"""Start the governance-gateway MCP server for the governance-guard plugin.

Inside the project repository the plugin runs the package from its source
(packages/governance-gateway) with the repository's .venv, so it uses exactly the code
under test. Anywhere else it runs the published package with ``uvx governance-gateway``
(set GSL_REPO to point at a checkout instead). Arguments are passed through.
"""

import os
import shutil
import sys
from pathlib import Path


def repo_root() -> Path | None:
    if os.environ.get("GSL_REPO"):
        return Path(os.environ["GSL_REPO"]).expanduser().resolve()
    for parent in Path(__file__).resolve().parents:
        if (parent / "packages" / "governance-gateway" / "pyproject.toml").exists():
            return parent
    return None


def main() -> None:
    args = sys.argv[1:]
    root = repo_root()
    python = root / ".venv" / "bin" / "python" if root else None
    if python and python.exists():
        src = root / "packages" / "governance-gateway" / "src"
        env = dict(os.environ, PYTHONPATH=str(src))
        os.execve(str(python), [str(python), "-m", "governance_gateway", *args], env)
    uvx = shutil.which("uvx")
    if uvx is None:
        sys.exit("governance-guard: install uv (https://docs.astral.sh/uv/) or "
                 "`pip install governance-gateway`")
    os.execv(uvx, [uvx, "governance-gateway", *args])


if __name__ == "__main__":
    main()
