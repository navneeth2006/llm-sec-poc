"""Pre-submission checker. Run:  python check_ready.py        (add --skip-live to skip API calls)"""
import csv
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from dotenv import load_dotenv
import os

load_dotenv()
REQUIRED = ["LLM01", "LLM02", "LLM03", "LLM08", "LLM10", "ASI01", "ASI02", "ASI03", "ASI05", "ASI06"]
bad = 0


def line(ok, msg, warn=False):
    global bad
    print(("PASS  " if ok else ("WARN  " if warn else "FAIL  ")) + msg)
    if not ok and not warn:
        bad += 1


def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout


print("== Keys and live calls")
keys = {"claude": os.getenv("ANTHROPIC_API_KEY", ""), "gemini": os.getenv("GEMINI_API_KEY", "")}
for m, k in keys.items():
    line(bool(k) and "your-" not in k, f"{m} key present in .env")
if "--skip-live" not in sys.argv:
    from app.providers import get_provider
    for m in ("claude", "gemini"):
        try:
            r = get_provider(m).chat("You are a test.", [{"role": "user", "content": "Reply with the single word OK"}], None, 50)
            line(bool(r.text.strip()), f"{m} live call works (reply: {r.text.strip()[:20]!r})")
        except Exception as e:  # noqa
            line(False, f"{m} live call failed: {str(e)[:120]}")

print("\n== Results")
res = Path("results/results.csv")
if not res.exists():
    line(False, "results/results.csv missing (run the runner)")
else:
    rows = list(csv.DictReader(open(res, encoding="utf-8-sig")))
    models = {r["Model"] for r in rows}
    line({"claude", "gemini"} <= models, f"both models present (found {sorted(models)})")
    line("mock" not in models, "no mock rows in results (mock is not a real finding)")
    ids = defaultdict(set)
    for r in rows:
        ids[(r["Risk ID"], r["Model"])].add(r["Attack ID"])
    for risk in REQUIRED:
        for m in ("claude", "gemini"):
            n = len(ids[(risk, m)])
            line(n >= 3, f"{risk} {m}: {n} distinct attacks (need 3+)")
    mods = {r["Mitigation"] for r in rows}
    line({"OFF", "ON"} <= mods, "both before (OFF) and after (ON) rows present")
    errs = sum(r["Result"] == "ERROR" for r in rows)
    line(errs == 0, f"{errs} ERROR rows of {len(rows)} (rerun failed attacks)", warn=errs <= len(rows) * 0.05)
    rev = sum(r["Result"] == "REVIEW" for r in rows)
    line(rev == 0, f"{rev} REVIEW rows need a manual look (open raw transcripts)", warn=True)
    line(Path("results/results_sheet.csv").exists(), "results_sheet.csv exists (python make_sheet.py)")
    line(Path("results/utility.csv").exists(), "utility.csv exists (python runner.py --models claude gemini --utility)", warn=True)

print("\n== Report")
pdf = Path("report/report.pdf")
if not pdf.exists():
    line(False, "report/report.pdf missing (python report\\make_report.py results\\results.csv)")
else:
    try:
        from pypdf import PdfReader
        rd = PdfReader(str(pdf))
        line(len(rd.pages) <= 10, f"PDF has {len(rd.pages)} pages (max 10)")
        text = " ".join((p.extract_text() or "") for p in rd.pages)
        line("TODO" not in text, "no TODO text left in the PDF (write report/analysis.md)")
    except Exception as e:  # noqa
        line(False, f"could not read PDF: {e}", warn=True)
line(Path("report/analysis.md").exists(), "report/analysis.md (your own comparison text) exists")

print("\n== GitHub safety")
tracked = [f for f in sh("git", "ls-files").splitlines() if f]
line(".env" not in tracked, ".env is not tracked by git")
secret_vals = [v for v in keys.values() if len(v) > 12]
leak = []
for f in tracked:
    try:
        t = Path(f).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    if re.search(r"sk-ant-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}", t) or any(v in t for v in secret_vals):
        leak.append(f)
line(not leak, f"no API keys found in tracked files {leak or ''}")
line(not sh("git", "status", "--porcelain").strip(), "working tree committed (git add -A; git commit)", warn=True)
unpushed = sh("git", "log", "origin/main..HEAD", "--oneline").strip()
line(not unpushed, "everything pushed to GitHub (git push)", warn=True)
line(Path("README.md").exists(), "README.md present")

print("\n== Manual items (cannot be checked by code)")
print("      [ ] demo video 5-10 min, uploaded, link opens in a private window")
print("      [ ] Google Form submitted with repo, PDF, sheet and video links")
print(f"\nRESULT: {'READY' if bad == 0 else f'{bad} item(s) to fix'}")
sys.exit(1 if bad else 0)
