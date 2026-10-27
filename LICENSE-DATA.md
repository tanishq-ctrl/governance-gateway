# Licences of the bundled data files

The files in `src/governance_gateway/data/` are not covered by the MIT licence of the code.

| File | Contents | Derived from | Licence |
|---|---|---|---|
| `guardrail.json` | Safety classifier (vocabulary, idf, weights) | ToxicChat 0124 training split | CC BY-NC 4.0 |
| `screen.json` | Suspicion screen (vocabulary, idf, weights) | ToxicChat 0124 training split | CC BY-NC 4.0 |
| `parity.json` | Synthetic test sentences and the expected model scores | the two models above | CC BY-NC 4.0 |
| `workload.json` | Per-message labels, verdicts and measured check costs of the ToxicChat test split (no message text), and conversation times from WildChat-1M | ToxicChat 0124 test split; WildChat-1M | CC BY-NC 4.0 (ToxicChat-derived fields); ODC-BY (WildChat times) |
| `study.json` | Breaking loads from the Governance Speed Lag simulation study | the author's own simulations | CC BY 4.0 |

**Non-commercial use only.** Because the two models and the workload labels are derived
from ToxicChat, which is licensed under Creative Commons Attribution-NonCommercial 4.0
(https://creativecommons.org/licenses/by-nc/4.0/), they may be used, shared and adapted
for non-commercial purposes only, with attribution. To use the gateway commercially,
replace the two models with your own.

## Attribution

- ToxicChat: Lin, Z., Wang, Z., Tong, Y., Wang, Y., Guo, Y., Wang, Y., & Shang, J. (2023).
  ToxicChat: Unveiling hidden challenges of toxicity detection in real-world user-AI
  conversation. Findings of EMNLP 2023. Data set: https://huggingface.co/datasets/lmsys/toxic-chat
- WildChat-1M: Zhao, W., Ren, X., Hessel, J., Cardie, C., Choi, Y., & Deng, Y. (2024).
  WildChat: 1M ChatGPT interaction logs in the wild. ICLR 2024. Data set (ODC-BY):
  https://huggingface.co/datasets/allenai/WildChat-1M
- Simulation study and models: Prabhu, T. S. (2026). Quantifying "Governance Speed Lag"
  (GSL) in Agentic AI Ecosystems: A simulation-based framework for self-adaptive
  real-time data compliance. MSc Data Science project, VIT.
