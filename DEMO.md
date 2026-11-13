# Demo video script (target 7-8 minutes)

0:00 Intro (30s) + say it runs in a Docker sandbox with fake data: who you are, goal, the 10 required risks plus MCP.
0:30 Architecture (60s): show `app/` (chatbot, agent, tool runtime), say "same code for Claude and Gemini".
1:30 Live attack 1, LLM01 (90s): run LLM01-A1 on Claude with no mitigation, then with it. Show the leaked canary, then BLOCKED.
3:00 Live attack 2, agent (90s): ASI01-A1 poisoned file makes the agent email attacker@evil.test. Show the outbox. Turn on mitigation and rerun.
4:30 MCP (90s): run MCP-A2 rug pull. Show `logs/mcp_rugpull_received.log` (what the evil server got). Then show the alert from pinning.
6:00 Full results (60s): `python runner.py --models claude gemini` summary table, open results.csv in Sheets.
7:00 Claude vs Gemini findings (60s): 2 or 3 differences from `python analyze.py`.
8:00 Limits and next steps (30s): non-determinism, regex filters are bypassable, usability trade-off.

Tips: run the long full test BEFORE recording, only demo 3 attacks live. Hide `.env`. Speak slowly. Say what each result means.
