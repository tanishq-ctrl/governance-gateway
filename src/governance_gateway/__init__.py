"""governance-gateway: deadline-aware governance checks for AI agents, over MCP.

From the MSc project "Quantifying Governance Speed Lag (GSL) in Agentic AI Ecosystems".
The personal-data check always runs; the slower safety classifier runs only if a cheap
screen finds the text suspicious and the classifier can still finish before the
request's deadline.
"""

__version__ = "0.1.1"
