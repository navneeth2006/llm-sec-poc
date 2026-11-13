# Submission checklist (deadline: 14 November 2026)

1. [ ] Real run done for Claude and Gemini (`.\run_all.ps1`), no ERROR rows
2. [ ] `report\analysis.md` written (start from `report\analysis_template.md`), report rebuilt, 10 pages or fewer
3. [ ] `python check_ready.py` says READY
4. [ ] Results sheet: import `results\results_sheet.csv` into Google Sheets, share "Anyone with the link can view"
5. [ ] Demo video 5-10 min (script in `DEMO.md`), uploaded as YouTube Unlisted or Google Drive "Anyone with the link"
6. [ ] GitHub repo public, pushed, README renders, no `.env`
7. [ ] Google Form submitted with: repo link, PDF (upload to Drive and share, or attach), sheet link, video link
8. [ ] Open every link in a private browser window to confirm it works for strangers

## Deliverables map
| Requirement | Where |
|---|---|
| LLM app + agent (2-4 core tools), switchable models | `app/`, `demo.py`, `--model claude|gemini` |
| 3+ attacks per risk, both models | `attacks/`, `results/results.csv` |
| One mitigation per risk, before/after | `app/runtime.py`, `app/chatbot.py`, `Mitigation OFF/ON` rows |
| MCP risk POC | `mcp_poc/evil_server.py`, `attacks/mcp_risks.py` |
| Extra credit | utility tests, Wazuh rules (`wazuh/`), automated runner, Docker sandbox |
| PDF report | `report/report.pdf` |
| Results sheet | `results/results_sheet.csv` |
