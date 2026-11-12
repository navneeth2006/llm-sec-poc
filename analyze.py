"""Helps you write the Claude vs Gemini analysis. Usage: python analyze.py results\\results.csv"""
import csv
import sys
from collections import defaultdict

rows = list(csv.DictReader(open(sys.argv[1] if len(sys.argv) > 1 else "results/results.csv", encoding="utf-8-sig")))
HIT = ("VULNERABLE", "REVIEW")
by = defaultdict(list)
for r in rows:
    by[(r["Attack ID"], r["Model"], r["Mitigation"])].append(r["Result"])
models = sorted({r["Model"] for r in rows})
ids = sorted({r["Attack ID"] for r in rows})


def rate(aid, m, mit):
    v = [x for x in by.get((aid, m, mit), []) if x != "ERROR"]
    return (sum(x in HIT for x in v), len(v)) if v else None


print("== Attacks where the models DIFFER at baseline (best material for your comparison)")
for a in ids:
    rs = {m: rate(a, m, "OFF") for m in models}
    vals = [v[0] / v[1] for v in rs.values() if v]
    if len(vals) > 1 and max(vals) != min(vals):
        print(f"  {a}: " + ", ".join(f"{m} {v[0]}/{v[1]}" for m, v in rs.items() if v))
print("\n== Mitigations that did NOT fully work (still vulnerable after)")
for a in ids:
    for m in models:
        v = rate(a, m, "ON")
        if v and v[0]:
            print(f"  {a} {m}: {v[0]}/{v[1]} still succeed")
print("\n== Flaky attacks (mixed results across trials = non-determinism, mention in report)")
for (a, m, mit), v in sorted(by.items()):
    if len({x for x in v if x != 'ERROR'}) > 1:
        print(f"  {a} {m} mitigation={mit}: {v}")
print("\n== Rows to review by hand")
for r in rows:
    if r["Result"] in ("REVIEW", "ERROR"):
        print(f"  {r['Result']:6} {r['Attack ID']} {r['Model']} mitigation={r['Mitigation']} {r['Evidence'][:70]}")
