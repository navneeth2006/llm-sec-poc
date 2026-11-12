"""Run every attack against every model, with mitigations OFF (baseline) and ON (only that risk's mitigation).
Usage: python runner.py --models claude gemini
       python runner.py --models mock --risks LLM01 ASI02     (offline pipeline test)"""
import argparse
import csv
import json
import time
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from app import logger                      # noqa: E402
from app.providers import get_provider      # noqa: E402
from app.settings import Settings           # noqa: E402
from attacks import ALL_ATTACKS             # noqa: E402
from attacks.utility import UTILITY         # noqa: E402
from attacks.base import Ctx               # noqa: E402

COLS = ["Risk ID", "Attack ID", "Attack", "Model", "Mitigation", "Trial", "Prompt", "Result", "Evidence",
        "Response", "Tools Called", "Blocked By", "Input Tokens", "Output Tokens", "Timestamp"]


def clip(s, n):
    s = str(s).replace("\r", " ")
    return s if len(s) <= n else s[:n] + f"...[truncated, {len(s)} chars]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=["claude", "gemini"])
    ap.add_argument("--risks", nargs="*", default=[])
    ap.add_argument("--modes", nargs="+", default=["baseline", "mitigated"])
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--out", default="results/results.csv")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--utility", action="store_true", help="run benign tasks to measure mitigation side effects")
    a = ap.parse_args()

    attacks = [x for x in (UTILITY if a.utility else ALL_ATTACKS) if not a.risks or x.risk in a.risks]
    if a.utility and a.out == "results/results.csv":
        a.out = "results/utility.csv"
    if a.list:
        for x in attacks:
            print(f"{x.id:10} {x.risk:6} {x.name}")
        return
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    raw = Path("results/raw")
    raw.mkdir(parents=True, exist_ok=True)
    new = not out.exists()
    stats = defaultdict(lambda: [0, 0])     # (risk, model, mode) -> [hits, total]
    with open(out, "a", newline="", encoding="utf-8-sig") as f, \
            open(raw / "transcripts.jsonl", "a", encoding="utf-8") as rawf:
        w = csv.writer(f)
        if new:
            w.writerow(COLS)
        for model in a.models:
            provider = get_provider(model)
            for atk in attacks:
                for mode in a.modes:
                    settings = Settings() if mode == "baseline" else Settings.only(atk.risk)
                    for trial in range(1, a.trials + 1):
                        try:
                            r = atk.run(Ctx(provider, settings))
                            if a.utility:
                                label = "PASS" if r.success else "FAIL"
                            else:
                                label = "REVIEW" if (r.success and r.review) else ("VULNERABLE" if r.success else "BLOCKED")
                        except Exception as e:  # noqa
                            r = None
                            label = "ERROR"
                            err = repr(e)[:300]
                        mit = "OFF" if mode == "baseline" else "ON"
                        row = [atk.risk, atk.id, atk.name, model, mit, trial,
                               clip(r.prompt if r else "", 400), label, r.evidence if r else err,
                               clip(r.response if r else "", 500), clip(r.tools if r else "", 300),
                               r.blocked_by if r else "", r.in_tok if r else 0, r.out_tok if r else 0,
                               time.strftime("%Y-%m-%d %H:%M:%S")]
                        w.writerow(row)
                        f.flush()
                        rawf.write(json.dumps(dict(zip(COLS, row)) | {"FullResponse": r.response if r else ""}) + "\n")
                        logger.event("attack_result", risk=atk.risk, attack=atk.id, model=model, mitigation=mit, result=label)
                        s = stats[(atk.risk, model, mit)]
                        s[1] += 1
                        s[0] += label in ("VULNERABLE", "REVIEW", "PASS")
                        print(f"{atk.id:10} {model:7} mitigation={mit:3} trial={trial} -> {label}")
    print("\n" + ("Legitimate tasks passing (pass/total)" if a.utility else "Attack success rate (hits/total)"))
    print(f"{'risk':7}{'model':8}{'before':>10}{'after':>10}")
    for risk, model in sorted({(k[0], k[1]) for k in stats}):
        b, m = stats.get((risk, model, "OFF"), [0, 0]), stats.get((risk, model, "ON"), [0, 0])
        print(f"{risk:7}{model:8}{b[0]:>5}/{b[1]:<4}{m[0]:>5}/{m[1]:<4}")
    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
