from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#7F1D1D"),
    "high": colors.HexColor("#DC2626"),
    "medium": colors.HexColor("#D97706"),
    "low": colors.HexColor("#2563EB"),
    "info": colors.HexColor("#6B7280"),
}
VERDICT_COLORS = {
    "Compromised": SEVERITY_COLORS["critical"],
    "Likely Compromised": SEVERITY_COLORS["high"],
    "Suspicious": SEVERITY_COLORS["medium"],
    "No Significant Findings": colors.HexColor("#15803D"),
}
INK = colors.HexColor("#111827")
MUTED = colors.HexColor("#6B7280")
RULE = colors.HexColor("#E5E7EB")
HEADER_BG = colors.HexColor("#1F2937")
ZEBRA = colors.HexColor("#F9FAFB")

base = getSampleStyleSheet()
STYLES = {
    "title": ParagraphStyle("title", parent=base["Title"], fontSize=22, leading=26, textColor=INK, spaceAfter=4),
    "subtitle": ParagraphStyle("subtitle", parent=base["Normal"], fontSize=10, textColor=MUTED, alignment=TA_CENTER),
    "h1": ParagraphStyle("h1", parent=base["Heading1"], fontSize=15, leading=19, textColor=INK, spaceBefore=10, spaceAfter=6),
    "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=11.5, leading=15, textColor=INK, spaceBefore=4, spaceAfter=3),
    "body": ParagraphStyle("body", parent=base["Normal"], fontSize=9.5, leading=13, textColor=INK),
    "small": ParagraphStyle("small", parent=base["Normal"], fontSize=8, leading=10, textColor=INK),
    "mono": ParagraphStyle("mono", parent=base["Code"], fontSize=7.5, leading=9.5, textColor=INK, leftIndent=0),
    "cell_head": ParagraphStyle("cell_head", parent=base["Normal"], fontSize=8, leading=10, textColor=colors.white, fontName="Helvetica-Bold"),
    "verdict": ParagraphStyle("verdict", parent=base["Normal"], fontSize=16, leading=20, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_CENTER),
    "badge": ParagraphStyle("badge", parent=base["Normal"], fontSize=8, leading=10, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_CENTER),
}


def p(text, style="body"):
    return Paragraph(escape("" if text is None else str(text)), STYLES[style])


def fmt_size(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def key_value_table(rows, widths=(45 * mm, 125 * mm)):
    table = Table([[p(k, "small"), p(v, "mono" if len(str(v)) > 40 else "small")] for k, v in rows], colWidths=widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), ZEBRA),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def data_table(headers, rows, widths, highlight=None):
    body = [[p(h, "cell_head") for h in headers]]
    body += [[p(cell, "small") for cell in row] for row in rows]
    table = Table(body, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_BG),
        ("GRID", (0, 0), (-1, -1), 0.3, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ZEBRA]),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for index in highlight or []:
        style.append(("BACKGROUND", (0, index + 1), (-1, index + 1), colors.HexColor("#FEE2E2")))
    table.setStyle(TableStyle(style))
    return table


def badge(severity):
    table = Table([[p(severity.upper(), "badge")]], colWidths=[22 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLORS.get(severity, MUTED)),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return table


def finding_block(finding):
    header = Table(
        [[badge(finding["severity"]), Paragraph(f"<b>{escape(finding['id'])}</b>  {escape(finding['title'])}", STYLES["h2"])]],
        colWidths=[25 * mm, 145 * mm],
    )
    header.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    rows = [("Category", finding["category"]), ("Rule", finding["rule"])]
    if finding.get("process"):
        rows.append(("Process", f"{finding['process']} (PID {finding['pid']})" if finding.get("pid") is not None else finding["process"]))
    if finding.get("mitre"):
        rows.append(("MITRE ATT&CK", ", ".join(finding["mitre"])))
    rows += [(k, v) for k, v in finding.get("evidence", {}).items() if v]
    return KeepTogether([
        header,
        Spacer(1, 3),
        p(finding["description"]),
        Spacer(1, 4),
        key_value_table(rows),
        Spacer(1, 3),
        Paragraph(f"<b>Recommendation:</b> {escape(finding['recommendation'])}", STYLES["body"]),
        Spacer(1, 10),
    ])


def summary_section(results):
    summary = results["summary"]
    verdict = Table([[p(f"{summary['verdict']}  |  Risk Score {summary['score']}/100", "verdict")]], colWidths=[170 * mm])
    verdict.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), VERDICT_COLORS.get(summary["verdict"], MUTED)),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))

    counts = summary["counts"]
    severity_row = Table(
        [[p(s.upper(), "badge") for s in counts], [p(str(n), "verdict") for n in counts.values()]],
        colWidths=[34 * mm] * len(counts),
    )
    severity_row.setStyle(TableStyle(
        [("BACKGROUND", (i, 0), (i, 0), SEVERITY_COLORS[s]) for i, s in enumerate(counts)]
        + [("BACKGROUND", (0, 1), (-1, 1), HEADER_BG), ("GRID", (0, 0), (-1, -1), 1, colors.white)]
    ))

    processes = results["processes"]
    narrative = (
        f"MemTrace analyzed the memory image <b>{escape(results['evidence']['file_name'])}</b> and identified "
        f"<b>{summary['total']}</b> finding(s) across {len(processes)} recovered processes, "
        f"{len(results['connections'])} network artifacts and {len(results['injections'])} suspicious memory regions. "
    )
    top = [f for f in results["findings"] if f["severity"] in ("critical", "high")][:5]
    if top:
        narrative += "The most significant findings are listed below and detailed in Section 3."
    else:
        narrative += "No critical or high severity indicators were identified by the automated rules."

    flow = [verdict, Spacer(1, 8), severity_row, Spacer(1, 10), Paragraph(narrative, STYLES["body"]), Spacer(1, 6)]
    if top:
        flow.append(data_table(
            ["ID", "Severity", "Finding"],
            [[f["id"], f["severity"].upper(), f["title"]] for f in top],
            [18 * mm, 22 * mm, 130 * mm],
        ))
    return flow


def on_page(case_id):
    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(HEADER_BG)
        canvas.rect(0, A4[1] - 12 * mm, A4[0], 12 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(20 * mm, A4[1] - 7.5 * mm, "MemTrace  |  Memory Forensics Report")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(A4[0] - 20 * mm, A4[1] - 7.5 * mm, f"Case {case_id}")
        canvas.setFillColor(MUTED)
        canvas.drawString(20 * mm, 10 * mm, "CONFIDENTIAL - Prepared for authorized investigators only")
        canvas.drawRightString(A4[0] - 20 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()
    return draw


def build_report(results, output_path):
    doc = SimpleDocTemplate(
        str(output_path), pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=20 * mm, bottomMargin=18 * mm,
        title=f"Memory Forensics Report {results['case_id']}", author="MemTrace",
    )
    evidence = results["evidence"]
    analysis = results["analysis"]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    story = [
        Spacer(1, 6),
        p("Memory Forensics Report", "title"),
        p(f"Case {results['case_id']}  |  Generated {generated}", "subtitle"),
        Spacer(1, 12),
        p("1. Executive Summary", "h1"),
        *summary_section(results),
        p("2. Evidence and Methodology", "h1"),
        p("Evidence Item", "h2"),
        key_value_table([
            ("File Name", evidence["file_name"]),
            ("Size", f"{fmt_size(evidence['size_bytes'])} ({evidence['size_bytes']:,} bytes)"),
            ("SHA-256", evidence["sha256"]),
            ("MD5", evidence["md5"]),
            ("Integrity", "Verified - hash unchanged after analysis" if evidence["integrity_verified"] else "FAILED - hash changed during analysis"),
        ]),
        Spacer(1, 6),
        p("Analysis Environment", "h2"),
        key_value_table([
            ("Tool", analysis["tool"]),
            ("Analysis Engine", analysis["engine"]),
            ("Python", analysis["python"]),
            ("Analyst OS", analysis["analyst_os"]),
            ("Started (UTC)", analysis["started_utc"]),
            ("Finished (UTC)", analysis["finished_utc"]),
        ]),
    ]

    if results.get("system"):
        story += [Spacer(1, 6), p("Target System Profile", "h2"), key_value_table(list(results["system"].items()))]

    story += [
        Spacer(1, 6),
        p("Methodology", "h2"),
        p(
            "The evidence was hashed before and after analysis to demonstrate that it was not modified. Volatility 3 "
            "plugins were executed against the image to enumerate processes from the active process list (pslist) and "
            "by pool scanning (psscan), reconstruct the process tree and command lines, list loaded modules (dlllist), "
            "read the AppInit_DLLs registry value from the in-memory registry (printkey), recover network artifacts "
            "(netscan) and locate private executable memory regions (malfind). MemTrace detection rules then compared "
            "these sources to identify hidden processes, masquerading processes and modules, abnormal parent-child "
            "relationships, DLL injection persistence, suspicious network activity and code injection."
        ),
        Spacer(1, 6),
        data_table(
            ["Plugin", "Status", "Detail", "Time (s)"],
            [[x["plugin"], x["status"].upper(), x["detail"], x["seconds"]] for x in results["plugins"]],
            [62 * mm, 16 * mm, 76 * mm, 16 * mm],
            highlight=[i for i, x in enumerate(results["plugins"]) if x["status"] != "ok"],
        ),
        PageBreak(),
        p("3. Detailed Findings", "h1"),
    ]

    if results["findings"]:
        story += [finding_block(f) for f in results["findings"]]
    else:
        story.append(p("No findings were generated by the automated detection rules."))

    story += [PageBreak(), p("4. Process Listing", "h1")]
    processes = results["processes"]
    story.append(data_table(
        ["PID", "PPID", "Name", "Created", "Source", "Flags"],
        [[x["pid"], x["ppid"], x["name"], (x["create_time"] or "")[:19], x["source"], ", ".join(x["flags"])] for x in processes],
        [14 * mm, 14 * mm, 36 * mm, 38 * mm, 18 * mm, 50 * mm],
        highlight=[i for i, x in enumerate(processes) if x.get("suspicious")],
    ))

    story += [Spacer(1, 8), p("5. Network Artifacts", "h1")]
    if results["connections"]:
        story.append(data_table(
            ["Proto", "Local", "Remote", "State", "PID", "Owner"],
            [[c["proto"], f"{c['local_addr']}:{c['local_port']}", f"{c['foreign_addr']}:{c['foreign_port']}", c["state"], c["pid"], c["owner"]] for c in results["connections"]],
            [14 * mm, 40 * mm, 40 * mm, 24 * mm, 14 * mm, 38 * mm],
            highlight=[i for i, c in enumerate(results["connections"]) if c["flags"]],
        ))
    else:
        failed = any(x["plugin"] == "windows.netscan" and x["status"] != "ok" for x in results["plugins"])
        story.append(p(
            "Network artifacts could not be recovered for this image (windows.netscan is not supported for this "
            "Windows version)." if failed else "No network artifacts were recovered."
        ))

    story += [
        Spacer(1, 12),
        p("6. Limitations", "h1"),
        p(
            "This report was produced by automated analysis. Findings are investigative leads that should be validated "
            "by a qualified examiner. Absence of findings does not prove the system was not compromised; memory "
            "captures only a point-in-time state and advanced malware may evade these detection rules."
        ),
    ]

    doc.build(story, onFirstPage=on_page(results["case_id"]), onLaterPages=on_page(results["case_id"]))
    return output_path
