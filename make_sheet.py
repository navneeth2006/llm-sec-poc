"""Builds the submission results sheet: results/results_sheet.csv with Risk ID, Model, Prompt, Result first.
Import that file into Google Sheets (File > Import > Upload)."""
import csv
import sys
from pathlib import Path

src = Path(sys.argv[1] if len(sys.argv) > 1 else "results/results.csv")
dst = Path("results/results_sheet.csv")
rows = [r for r in csv.DictReader(open(src, encoding="utf-8-sig"))]
cols = ["Risk ID", "Model", "Prompt", "Result", "Mitigation", "Attack ID", "Attack", "Trial", "Evidence"]
with open(dst, "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(cols)
    for r in rows:
        w.writerow([r[c] for c in cols])
print(f"Wrote {dst} ({len(rows)} rows). Mitigation OFF = before, ON = after.")
