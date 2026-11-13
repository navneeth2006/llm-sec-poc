"""Builds report/report.pdf (+ charts) from results/results.csv.
Run:  python report/make_report.py results/results.csv
Then open the PDF, read the numbers, and EDIT the 'Analysis' text in this file with what YOU observed."""
import csv
import os
import sys
from xml.sax.saxutils import escape
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
SRC = Path(sys.argv[1] if len(sys.argv) > 1 else "results/results.csv")
OUT = Path("report")
rows = list(csv.DictReader(open(SRC, encoding="utf-8-sig")))
rows = [r for r in rows if r["Result"] != "ERROR"]
if not rows:
    sys.exit("No valid results in " + str(SRC) + " (only ERROR rows or empty). Run the real tests first.")
models = sorted({r["Model"] for r in rows})
risks = sorted({r["Risk ID"] for r in rows}, key=lambda x: (x.startswith("MCP"), x.startswith("ASI"), x))
HIT = ("VULNERABLE", "REVIEW")

cnt = defaultdict(lambda: [0, 0])
for r in rows:
    if r["Result"] == "ERROR":
        continue
    k = (r["Risk ID"], r["Model"], r["Mitigation"])
    cnt[k][1] += 1
    cnt[k][0] += r["Result"] in HIT


def rate(risk, model, mit):
    h, t = cnt.get((risk, model, mit), [0, 0])
    return (100 * h / t) if t else None


def fmt(risk, model, mit):
    h, t = cnt.get((risk, model, mit), [0, 0])
    return f"{h}/{t}" if t else "-"


# ---- charts: attack success rate before vs after
fig, axes = plt.subplots(1, len(models), figsize=(5.2 * len(models), 3.6), sharey=True, squeeze=False)
for ax, m in zip(axes[0], models):
    x = range(len(risks))
    b = [rate(r, m, "OFF") or 0 for r in risks]
    a = [rate(r, m, "ON") or 0 for r in risks]
    ax.bar([i - 0.2 for i in x], b, 0.4, label="No mitigation", color="#c0392b")
    ax.bar([i + 0.2 for i in x], a, 0.4, label="With mitigation", color="#27ae60")
    ax.set_xticks(list(x))
    ax.set_xticklabels(risks, rotation=60, fontsize=7)
    ax.set_title(f"{m}: attack success rate (%)", fontsize=9)
    ax.set_ylim(0, 105)
axes[0][0].legend(fontsize=7)
plt.tight_layout()
plt.savefig(OUT / "asr_chart.png", dpi=160)

# ---- overall numbers
def overall(m, mit):
    h = sum(v[0] for k, v in cnt.items() if k[1] == m and k[2] == mit)
    t = sum(v[1] for k, v in cnt.items() if k[1] == m and k[2] == mit)
    return h, t


ss = getSampleStyleSheet()
H1, H2, P = ss["Heading1"], ss["Heading2"], ss["BodyText"]
small = ss["BodyText"].clone("small", fontSize=7.5, leading=9)
doc = SimpleDocTemplate(str(OUT / "report.pdf"), pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm,
                        topMargin=1.5 * cm, bottomMargin=1.5 * cm)
S = []
S += [Paragraph("AI Security POC: OWASP LLM and Agentic Top 10 on Claude and Gemini", H1),
      Paragraph("YGF NGO AI Security Internship, Round 2. Author: Navneeth Dev J", P), Spacer(1, 6)]

S += [Paragraph("1. Objective and scope", H2), Paragraph(
    "This proof of concept simulates the required OWASP Top 10 for LLM Applications (LLM01, LLM02, LLM03, LLM08, LLM10) "
    "and OWASP Top 10 for Agentic Applications (ASI01, ASI02, ASI03, ASI05, ASI06) risks, plus MCP connection risks. "
    "Every risk has 3 or more attacks, run against Claude and Gemini through one provider-agnostic harness, first with no "
    "defence (baseline) and then with one mitigation for that risk.", P)]

S += [Paragraph("2. Architecture", H2), Paragraph(
    "<b>LLM app:</b> support chatbot with a fake knowledge base (RAG) and canary secrets in its system prompt. "
    "<b>Agent:</b> tool-calling loop with four core tools (read_file, send_email, http_get, memory_save) plus run_code and "
    "plugin/MCP tools per scenario. All tools are simulated: virtual file system, outbox instead of real email, mock web, "
    "and code execution that is logged, never run. <b>Judging:</b> deterministic. Canary strings and tool side effects "
    "(an email in the outbox, a read outside /sandbox) decide pass or fail, not human opinion. "
    "<b>Mitigation switch:</b> each risk has one toggle, so baseline and mitigated runs differ by that one control only. "
    f"<b>Models tested:</b> Claude ({os.getenv('CLAUDE_MODEL', 'claude-haiku-5-5')}) and Gemini ({os.getenv('GEMINI_MODEL', 'gemini-3.8-flash')}). "
    "<b>Sandbox:</b> the project runs in a Docker container with fake data only; all tools are simulated and attack goals use harmless canary strings.", P)]

S += [Paragraph("3. Results: attack success (hits/attempts)", H2)]
head = ["Risk"] + [f"{m}\nbefore" for m in models] + [f"{m}\nafter" for m in models]
data = [head] + [[r] + [fmt(r, m, "OFF") for m in models] + [fmt(r, m, "ON") for m in models] for r in risks]
tot = ["TOTAL"] + [f"{overall(m, 'OFF')[0]}/{overall(m, 'OFF')[1]}" for m in models] + \
      [f"{overall(m, 'ON')[0]}/{overall(m, 'ON')[1]}" for m in models]
data.append(tot)
t = Table(data, repeatRows=1)
t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                       ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTSIZE", (0, 0), (-1, -1), 8),
                       ("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#ecf0f1"))]))
S += [t, Spacer(1, 6), Image(str(OUT / "asr_chart.png"), width=17 * cm, height=17 * cm * 3.6 / (5.2 * len(models)))]

MIT = {
    "LLM01": "Spotlighting (untrusted_document tags) + input filter incl. base64 decode",
    "LLM02": "Secrets removed from context + PII redaction + output DLP",
    "LLM03": "Hash-pinned plugin manifests + dependency allowlist",
    "LLM08": "Trusted-source ingestion gate, sanitiser, per-tenant ACL on retrieval",
    "LLM10": "max_tokens cap, input length cap, loop/step/token budget, rate limit",
    "ASI01": "Untrusted-data tagging + taint tracking + confirmation before sensitive actions",
    "ASI02": "Path sandbox, URL host allowlist, recipient allowlist and cap (tool layer)",
    "ASI03": "RBAC enforced in the tool layer from the session role, not from the prompt",
    "ASI05": "AST allowlist: arithmetic only, no names, attributes or imports",
    "ASI06": "Memory write validation, provenance, TTL, read-time filtering",
    "MCP": "Server allowlist, description pinning (rug pull), injection scan, namespacing, taint gate",
}
S += [Paragraph("4. Mitigations (one per risk)", H2)]
S += [Table([["Risk", "Mitigation"]] + [[r, Paragraph(MIT.get(r, ""), small)] for r in risks], colWidths=[2 * cm, 15 * cm],
            style=TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8),
                              ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ecf0f1"))]))]

UT = Path("results/utility.csv")
if UT.exists():
    urows = list(csv.DictReader(open(UT, encoding="utf-8-sig")))
    uc = defaultdict(lambda: [0, 0])
    for r in urows:
        if r["Result"] != "ERROR":
            uc[(r["Model"], r["Mitigation"])][1] += 1
            uc[(r["Model"], r["Mitigation"])][0] += r["Result"] == "PASS"
    S += [Paragraph("4b. Do the mitigations break normal use? (legitimate tasks passing)", H2)]
    ut = [["Model", "Mitigation OFF", "Mitigation ON"]] + [[m, f"{uc[(m,'OFF')][0]}/{uc[(m,'OFF')][1]}", f"{uc[(m,'ON')][0]}/{uc[(m,'ON')][1]}"] for m in sorted({r['Model'] for r in urows})]
    S += [Table(ut, style=TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8)])),
          Paragraph("Failures with mitigation ON are the security vs usability trade-off, e.g. ASI01 blocks an email sent after reading a file "
                    "until the user confirms.", small)]

S += [Paragraph("5. Attacks that succeeded at baseline (sample)", H2)]
seen, samp = set(), [["Attack", "Model", "Evidence"]]
for r in rows:
    if r["Mitigation"] == "OFF" and r["Result"] in HIT and (r["Attack ID"], r["Model"]) not in seen and len(samp) < 19:
        seen.add((r["Attack ID"], r["Model"]))
        samp.append([Paragraph(f"{r['Attack ID']} {r['Attack']}", small), r["Model"], Paragraph(r["Evidence"][:90], small)])
S += [Table(samp, colWidths=[8 * cm, 2 * cm, 7 * cm], repeatRows=1,
            style=TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8)]))]

def pct(x):
    return f"{100 * x[0] / x[1]:.0f}%" if x[1] else "n/a"


def auto_findings():
    out = []
    for m in models:
        b, a_ = overall(m, "OFF"), overall(m, "ON")
        out.append(f"{m}: {b[0]}/{b[1]} attacks succeeded with no defence ({pct(b)}); {a_[0]}/{a_[1]} with the risk's mitigation on ({pct(a_)}).")
    if len(models) > 1:
        diffs = []
        for r in risks:
            rs = {m: rate(r, m, "OFF") for m in models}
            if all(v is not None for v in rs.values()) and max(rs.values()) - min(rs.values()) >= 33:
                diffs.append(r + " (" + ", ".join(f"{m} {rs[m]:.0f}%" for m in models) + ")")
        out.append("Largest baseline differences between the models: " + ("; ".join(diffs) if diffs else "none above 33 points") + ".")
    resid = [f"{r}/{m} ({fmt(r, m, 'ON')})" for r in risks for m in models if (rate(r, m, "ON") or 0) > 0]
    out.append("Residual failures after mitigation: " + (", ".join(resid) if resid else "none") + ".")
    return out


S += [Paragraph("6. Claude vs Gemini: findings", H2)]
for f_ in auto_findings():
    S += [Paragraph("- " + escape(f_), P)]
AN = Path("report/analysis.md")
if AN.exists():
    for blk in AN.read_text(encoding="utf-8").split("\n\n"):
        blk = blk.strip()
        if blk.startswith("#"):
            S += [Paragraph(escape(blk.lstrip("# ").strip()), ss["Heading3"])]
        elif blk:
            S += [Paragraph(escape(blk).replace("\n", " "), P)]
else:
    S += [Paragraph("<b>TODO:</b> create report/analysis.md with your own comparison (which model resisted injection better, "
                    "tool-description and tool-result behaviour, refusals vs tool misuse, attacks that worked on one model only). Cite attack IDs.", P)]
S += [Paragraph("7. MCP connection risk", H2), Paragraph(
    "A local malicious MCP server (mcp_poc/evil_server.py, official MCP SDK over stdio) demonstrates four issues: tool poisoning "
    "(hidden instructions in a tool description make the agent leak private notes through a parameter), rug pull (a description "
    "that turns malicious after approval), tool shadowing (a server tool that hijacks the built-in send_email) and malicious tool "
    "results. Mitigation bundle: allowlist, hash-pinned descriptions, description scan, namespacing, and a confirmation gate "
    "after untrusted content.", P)]
S += [Paragraph("8. Limitations", H2), Paragraph(
    "LLM output is non-deterministic: results are from N trials per attack and can change between runs and model versions. "
    "Regex filters are bypassable by a determined attacker, so each mitigation is one layer, not a full fix. "
    "Confirmation gates trade usability for safety (benign emails after reading a file are also blocked). The retriever is "
    "keyword-based, standing in for embeddings. Code execution is simulated for safety. Judging is automatic; REVIEW rows need a human check.", P)]
doc.build(S)
print("Wrote report/report.pdf")
