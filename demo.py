"""Interactive demo: talk to the chatbot or the agent, with any mitigations switched on.
  python demo.py --mode chatbot --model gemini
  python demo.py --mode agent --model claude --mitigate ASI01 ASI02
Commands inside:  /run LLM01-A1   run a stored attack with the current settings
                  /attacks        list attack ids      /quit
"""
import argparse

from dotenv import load_dotenv

load_dotenv()

from app.agent import Agent                      # noqa: E402
from app.chatbot import Chatbot                  # noqa: E402
from app.env import Env                          # noqa: E402
from app.providers import get_provider           # noqa: E402
from app.settings import ALL_RISKS, Settings     # noqa: E402
from attacks import ALL_ATTACKS                  # noqa: E402
from attacks.base import ACME, ADMIN, INTERN, Ctx   # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--mode", choices=["chatbot", "agent"], default="chatbot")
ap.add_argument("--model", default="gemini", help="claude | gemini | mock")
ap.add_argument("--mitigate", nargs="*", default=[], help="risk ids, e.g. LLM01 ASI02 (or: all)")
ap.add_argument("--user", choices=["intern", "admin"], default="intern", help="agent user role")
a = ap.parse_args()

risks = ALL_RISKS if a.mitigate == ["all"] else a.mitigate
bad = [r for r in risks if r not in ALL_RISKS]
if bad:
    raise SystemExit(f"unknown risk ids {bad}. Valid: {ALL_RISKS}")
settings = Settings(frozenset(risks))
provider = get_provider(a.model)
env = Env()
user = ADMIN if a.user == "admin" else INTERN
seen = 0
print(f"\nmode={a.mode} model={a.model} mitigations={sorted(risks) or 'NONE (vulnerable)'}")
print("Type a message. /run <ATTACK-ID>, /attacks, /quit\n")

while True:
    try:
        text = input("you> ").strip()
    except (EOFError, KeyboardInterrupt):
        break
    if not text:
        continue
    if text == "/quit":
        break
    if text == "/attacks":
        for x in ALL_ATTACKS:
            print(f"  {x.id:10} {x.name}")
        continue
    try:
        if text.startswith("/run"):
            aid = text.split()[-1]
            atk = next((x for x in ALL_ATTACKS if x.id == aid), None)
            if not atk:
                print("unknown attack id (see /attacks)")
                continue
            r = atk.run(Ctx(provider, settings))
            print(f"\n[{atk.id}] {atk.name}\nprompt  : {r.prompt[:300]}\nresponse: {r.response[:500]}")
            print(f"tools   : {r.tools or '-'}\nblocked : {r.blocked_by or '-'}")
            print(f"RESULT  : {'ATTACK SUCCEEDED (vulnerable)' if r.success else 'attack blocked'}  ({r.evidence})\n")
            continue
        if a.mode == "chatbot":
            out = Chatbot(provider, settings, env).answer(ACME, text)
            print(f"bot> {out.text}" + ("   [blocked by app]" if out.blocked else "") + "\n")
        else:
            out = Agent(provider, settings, env, user, ["read_file", "send_email", "http_get", "memory_save", "run_code"]).run(text)
            for t in env.tool_log[seen:]:
                print(f"  tool: {t['tool']}({str(t['args'])[:90]})")
            seen = len(env.tool_log)
            print(f"agent> {out.text}")
            if env.outbox:
                print(f"  outbox: {[m['to'] for m in env.outbox]}")
            if env.blocks:
                print(f"  mitigation blocks: {[b['detail'][:60] for b in env.blocks]}")
            print()
    except Exception as e:  # noqa
        print(f"error: {str(e)[:300]}\n")
