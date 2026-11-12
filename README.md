# LLM + Agentic AI Security POC (OWASP Top 10 2026) on Claude and Gemini

Proof of concept for the YGF NGO AI Security Internship, Round 2.
It simulates OWASP LLM and Agentic AI risks against **Claude** and **Gemini** (switchable), measures attack
success **before and after** one mitigation per risk, and demonstrates **MCP** connection risks.

> All data is fake. Tools are simulated (virtual file system, outbox instead of real email, mock web, code is
> logged not executed). No real API keys are in this repo.

## Coverage
| Risk | Attacks | Mitigation (toggle `--modes mitigated`) |
|---|---|---|
| LLM01 Prompt Injection | direct override, base64 payload, indirect via KB doc | spotlighting + input filter |
| LLM02 Sensitive Info Disclosure | system prompt extraction, PII, social-engineered key | secrets out of context + DLP |
| LLM03 Supply Chain | tampered plugin manifest, poisoned plugin update, typosquatted dependency | hash pinning + allowlist |
| LLM08 Vector/Embedding Weaknesses | poisoned external doc, cross-tenant retrieval, hidden text | ingestion gate + sanitiser + ACL |
| LLM10 Unbounded Consumption | huge output, recursive tool loop, input flood | token/step/input caps, loop breaker |
| ASI01 Agent Goal Hijack | poisoned file, web page, inbox message | untrusted tagging + taint + confirmation |
| ASI02 Tool Misuse | path traversal, SSRF, external email | sandbox + allowlists |
| ASI03 Identity/Privilege Abuse | confused deputy, claimed authority, planted approval | RBAC in tool layer |
| ASI05 Unexpected Code Exec | shell via code tool, obfuscated eval, code in doc | AST allowlist |
| ASI06 Memory/Context Poisoning | poisoned file to memory, poisoned address, cross-session plant | write validation + provenance + TTL |
| MCP | tool poisoning, rug pull, shadowing, malicious result | allowlist, pinning, scan, namespacing, taint gate |

Verify risk names against the official OWASP GenAI Security Project pages before submitting.

## Setup (Windows PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env      # then put your keys in .env
```
Keys: Gemini from Google AI Studio (free tier). Claude from console.anthropic.com (needs a few dollars of credit).

## Run
```powershell
python runner.py --list                                   # show all attacks
python runner.py --models mock --out results\mock.csv     # offline pipeline test (NOT real results)
python runner.py --models claude gemini --trials 3        # real run, writes results\results.csv
python runner.py --models claude gemini --risks LLM01 ASI02   # subset
python runner.py --models claude gemini --utility         # do mitigations break normal tasks? -> results\utility.csv
python analyze.py results\results.csv                      # where Claude and Gemini differ, flaky and failed cases
python report\make_report.py results\results.csv          # builds report\report.pdf
```
Use `--trials 3` or more: LLM output varies between runs.

## Try it by hand
```python
from dotenv import load_dotenv; load_dotenv()
from app.providers import get_provider
from app.settings import Settings
from attacks.base import Ctx
from attacks import ALL_ATTACKS
atk = next(a for a in ALL_ATTACKS if a.id == "LLM01-A1")
print(atk.run(Ctx(get_provider("claude"), Settings())))              # no defence
print(atk.run(Ctx(get_provider("claude"), Settings.only("LLM01"))))  # mitigation on
```

## Layout
- `app/` chatbot (RAG), agent loop, tool runtime and mitigations, providers (Claude, Gemini, mock), MCP bridge
- `attacks/` attack cases and deterministic judges
- `mcp_poc/evil_server.py` malicious MCP server (modes: poisoned, rugpull, shadow, result_injection)
- `runner.py` runs everything, writes `results/results.csv` + `results/raw/transcripts.jsonl`
- `report/make_report.py` PDF report builder
- `attacks/utility.py` benign tasks that measure mitigation side effects
- `analyze.py` comparison helper, `DEMO.md` video script
- `wazuh/` log forwarding rules (extra credit); events go to `logs/llm_security.log`

## Results columns
Risk ID, Attack ID, Attack, Model, Mitigation (OFF/ON), Trial, Prompt, Result (VULNERABLE / BLOCKED / REVIEW / ERROR),
Evidence, Response, Tools Called, Blocked By, tokens, Timestamp. Import the CSV into Google Sheets.
`REVIEW` = marker found but reply also looks like a refusal; check by hand.

## Add or change an attack
Add a `chat_attack(...)` or `agent_attack(...)` entry in `attacks/*.py`. Judges check tool side effects
(outbox, file reads, exec log), not model wording.

## Safety
Educational use on fake data only. Do not point this at systems you do not own.
