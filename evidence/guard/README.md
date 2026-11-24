# Evidence: AI tool guard

All files here were generated from real runs on Windows 11 / Python 3.12.10 (no Docker); nothing is mocked up.
Everything they show is simulated: the agent (obedient scripted agent), the tools, the workspace, the attacker sink and the secrets (planted canaries).

| File | What it shows | How it was made |
|---|---|---|
| `guard_demo.png` | The PS-CYB-02 example: guard OFF leaks the planted keys, guard ON blocks the secret read and the email | `shadowguard serve`, then headless Edge on `/guard/demo?scenario=hidden-text&autorun=1&shot=1` |
| `guard_attack_trail.png` | The guarded session: document with the hidden text highlighted, every attempted call with findings and matched rules, audit hashes | `/guard/session/<id>` |
| `guard_live_feed.png` | KPI tiles, why calls were stopped, live call table | `/guard` after the hidden-text, multi-step and rug-pull demos |
| `guard_approvals.png` | Two ASK items from the multi-step scenario waiting for a human | `/guard/approvals` |
| `guard_policy.png`, `guard_tool_integrity.png` | Roles/rules/what-if tester; the weather plugin quarantined after its rug pull | `/guard/policy`, `/guard/tools` |
| `demo_all_scenarios.txt` | Transcript of all 11 scenarios without and with the guard, plus the audit chain check | `shadowguard demo --scenario all --mode both` |

Benchmark output lives in `eval_guard/results/` (`shadowguard eval`).
