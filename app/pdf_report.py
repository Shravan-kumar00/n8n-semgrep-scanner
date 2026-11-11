"""PDF version of a scan report, built with ReportLab.

The PDF contains only the findings (never the scanned workflow / source or
code excerpts), grouped Critical -> High -> Medium -> Low. Each finding shows:
  * its severity, title and the line number(s) it comes from
  * a one-sentence brief
  * how to fix it
  * the exposed value, only when the user explicitly asked for it
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as pdf_canvas
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import RISK_ORDER, Finding, ScanResponse

SEVERITY = {
    "critical": ("Critical", colors.HexColor("#DC2626"), colors.HexColor("#FEF2F2")),
    "high": ("High", colors.HexColor("#EA580C"), colors.HexColor("#FFF7ED")),
    "medium": ("Medium", colors.HexColor("#D97706"), colors.HexColor("#FFFBEB")),
    "low": ("Low", colors.HexColor("#0284C7"), colors.HexColor("#F0F9FF")),
    "info": ("Info", colors.HexColor("#64748B"), colors.HexColor("#F8FAFC")),
}
INK = colors.HexColor("#0F172A")
MUTED = colors.HexColor("#64748B")
RULE = colors.HexColor("#E2E8F0")
FIX_BG, FIX_BORDER, FIX_INK = colors.HexColor("#ECFDF5"), colors.HexColor("#A7F3D0"), colors.HexColor("#064E3B")
SECRET_BG, SECRET_BORDER, SECRET_INK = colors.HexColor("#FEF2F2"), colors.HexColor("#FECACA"), colors.HexColor("#7F1D1D")

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

# The built-in PDF fonts only cover Windows-1252; map common symbols first.
_REPLACEMENTS = {"→": "->", "←": "<-", "⇒": "=>", "≥": ">=", "≤": "<=", "✓": "v", "✗": "x"}


def _plain(text: object) -> str:
    """Keep text within the built-in fonts' charset (for canvas drawString)."""
    value = str(text if text is not None else "")
    for src, dst in _REPLACEMENTS.items():
        value = value.replace(src, dst)
    return value.encode("cp1252", "replace").decode("cp1252")


def _safe(text: object) -> str:
    """_plain() plus escaping for ReportLab's Paragraph mini-markup."""
    return escape(_plain(text))


def _style(name: str, parent: ParagraphStyle | None = None, **kw) -> ParagraphStyle:
    if parent is not None:  # inherit everything not overridden
        return ParagraphStyle(name, parent=parent, **kw)
    base = {"fontName": "Helvetica", "fontSize": 10, "leading": 14, "textColor": INK}
    base.update(kw)
    return ParagraphStyle(name, **base)


S = {
    "title": _style("title", fontName="Helvetica-Bold", fontSize=22, leading=27),
    "subtitle": _style("subtitle", fontSize=11, leading=15, textColor=MUTED),
    "h2": _style("h2", fontName="Helvetica-Bold", fontSize=13, leading=17, spaceBefore=6, spaceAfter=6),
    "body": _style("body"),
    "small": _style("small", fontSize=8.5, leading=11, textColor=MUTED),
    "verdict_label": _style("verdict_label", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.white),
    "verdict": _style("verdict", fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=colors.white),
    "verdict_text": _style("verdict_text", fontSize=10.5, leading=14, textColor=colors.white),
    "count": _style("count", fontName="Helvetica-Bold", fontSize=20, leading=23, alignment=1),
    "count_label": _style("count_label", fontName="Helvetica-Bold", fontSize=8, leading=10, alignment=1),
    "th": _style("th", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=MUTED),
    "td": _style("td", fontSize=9, leading=12),
    "td_badge": _style("td_badge", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.white, alignment=1),
    "section": _style("section", fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=colors.white),
    "badge": _style("badge", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.white, alignment=1),
    "card_title": _style("card_title", fontName="Helvetica-Bold", fontSize=11.5, leading=15),
    "card_line": _style("card_line", fontName="Helvetica-Bold", fontSize=9.5, leading=12, alignment=TA_RIGHT),
    "label": _style("label", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=MUTED),
    "brief": _style("brief", fontSize=10.5, leading=14.5),
    "fix_label": _style("fix_label", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=FIX_INK),
    "fix": _style("fix", fontSize=10, leading=14, textColor=FIX_INK),
    "secret_label": _style("secret_label", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=SECRET_INK),
    "secret": _style("secret", fontName="Courier", fontSize=9, leading=12, textColor=SECRET_INK, wordWrap="CJK"),
}


def verdict(summary) -> tuple[str, str, str]:
    """(severity key for colour, label, sentence) - mirrors the web UI."""
    c, h, m = summary.critical, summary.high, summary.medium
    plural = lambda n, w: f"{n} {w}{'' if n == 1 else 's'}"  # noqa: E731
    if c:
        extra = f" and {plural(h, 'high issue')}" if h else ""
        return "critical", "Critical risk", f"Do not deploy yet: fix {plural(c, 'critical issue')}{extra} first."
    if h:
        return "high", "High risk", f"Fix {plural(h, 'high-severity issue')} before deploying."
    if m:
        return "medium", "Moderate risk", f"No critical or high issues. Review {plural(m, 'medium issue')}."
    if summary.total:
        return "low", "Low risk", "Only minor findings. Review them when convenient."
    return "none", "No issues found", "The rule set found nothing. Still review it manually before deploying."


def _lines(f: Finding) -> str:
    return f"Line {f.start_line}" if f.start_line == f.end_line else f"Lines {f.start_line}-{f.end_line}"


AREA_LABELS = {
    "secrets": "Secrets",
    "ai-agent": "AI agents",
    "integrations": "Integrations",
    "injection": "Injection",
    "code-execution": "Code execution",
    "crypto": "Cryptography",
    "configuration": "Configuration",
    "access-control": "Access control",
    "transport": "Transport",
    "data-exposure": "Data exposure",
}


def _node(f: Finding) -> str:
    if not f.node_name:
        return "Workflow-level"
    short = (f.node_type or "").replace("n8n-nodes-base.", "").replace("@n8n/n8n-nodes-langchain.", "AI ")
    return f"{f.node_name} ({short})" if short else f.node_name


class _NumberedCanvas(pdf_canvas.Canvas):
    """Adds "Page X of Y" and a running header once the page count is known."""

    def __init__(self, *args, header: str = "", generated: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_pages: list[dict] = []
        self._header = header
        self._generated = generated

    def showPage(self):  # noqa: N802 - ReportLab API
        self._saved_pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved_pages)
        for state in self._saved_pages:
            self.__dict__.update(state)
            self._decorate(total)
            super().showPage()
        super().save()

    def _decorate(self, total: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(MUTED)
        if self._pageNumber > 1:
            self.drawString(MARGIN, PAGE_H - 11 * mm, self._header)
            self.setStrokeColor(RULE)
            self.line(MARGIN, PAGE_H - 12.5 * mm, PAGE_W - MARGIN, PAGE_H - 12.5 * mm)
        self.drawString(MARGIN, 10 * mm, self._generated)
        self.drawRightString(PAGE_W - MARGIN, 10 * mm, f"Page {self._pageNumber} of {total}")
        self.restoreState()


def build_pdf(result: ScanResponse, include_secrets: bool = False, scanned_at: datetime | None = None) -> bytes:
    scanned_at = scanned_at or datetime.now(timezone.utc)
    is_workflow = result.node_count is not None
    name = result.target_name or result.workflow_name or (
        "Untitled workflow" if is_workflow else f"{result.language_label} file")
    scope = (f"n8n workflow · {result.node_count} nodes" if is_workflow
             else f"{result.language_label} · {result.line_count} lines")
    findings = sorted(result.findings, key=lambda f: (RISK_ORDER.index(f.risk), f.start_line, f.rule_id))
    number = {id(f): i for i, f in enumerate(findings, start=1)}

    story: list = []

    # ---------------------------------------------------------------- header
    story += [
        Paragraph("Security report", S["title"]),
        Spacer(1, 2 * mm),
        Paragraph(_safe(name), S["subtitle"]),
        Paragraph(
            _safe(f"Scanned {scanned_at.strftime('%d %b %Y, %H:%M UTC')} · {scope} · "
                  f"{'Credentials only' if result.profile == 'credentials' else 'All checks'}"),
            S["small"],
        ),
        Spacer(1, 6 * mm),
    ]

    key, label, sentence = verdict(result.summary)
    banner_color = SEVERITY[key][1] if key in SEVERITY else colors.HexColor("#059669")
    banner = Table(
        [[Paragraph("OVERALL RISK", S["verdict_label"])], [Paragraph(_safe(label), S["verdict"])], [Paragraph(_safe(sentence), S["verdict_text"])]],
        colWidths=[CONTENT_W],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), banner_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, 0), 10), ("BOTTOMPADDING", (0, -1), (-1, -1), 11),
        ("TOPPADDING", (0, 1), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -2), 1),
        ("ROUNDEDCORNERS", [6, 6, 6, 6]),
    ]))
    story += [banner, Spacer(1, 5 * mm)]

    # Severity counts (Info only when present).
    levels = [r for r in RISK_ORDER if r != "info" or result.summary.info]
    cells = [[
        [Paragraph(str(getattr(result.summary, r)), _style(f"c_{r}", parent=S["count"], textColor=SEVERITY[r][1])),
         Paragraph(SEVERITY[r][0].upper(), _style(f"cl_{r}", parent=S["count_label"], textColor=SEVERITY[r][1]))]
        for r in levels
    ]]
    gap = 3 * mm
    box_w = (CONTENT_W - gap * (len(levels) - 1)) / len(levels)
    counts = Table(cells, colWidths=[box_w] * len(levels), spaceBefore=0)
    style = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]
    for i, r in enumerate(levels):
        style += [("BACKGROUND", (i, 0), (i, 0), SEVERITY[r][2]), ("BOX", (i, 0), (i, 0), 0.75, SEVERITY[r][1])]
    counts.setStyle(TableStyle(style))
    story += [counts, Spacer(1, 7 * mm)]

    if not findings:
        story.append(Paragraph("No issues were found by the current rule set. Still review it manually before deploying.", S["body"]))
        return _render(story, name, scanned_at)

    # ------------------------------------------------------------ at a glance
    story.append(Paragraph("At a glance", S["h2"]))
    rows = [[Paragraph(h, S["th"]) for h in ("#", "SEVERITY", "ISSUE", "NODE" if is_workflow else "AREA", "LINE")]]
    for f in findings:
        rows.append([
            Paragraph(str(number[id(f)]), S["td"]),
            Paragraph(SEVERITY[f.risk][0].upper(), S["td_badge"]),
            Paragraph(_safe(f.title), S["td"]),
            Paragraph(_safe((f.node_name or "Workflow-level") if is_workflow else AREA_LABELS.get(f.category, f.category)), S["td"]),
            Paragraph(_safe(_lines(f).replace("Lines ", "").replace("Line ", "")), S["td"]),
        ])
    glance = Table(rows, colWidths=[9 * mm, 21 * mm, 80 * mm, CONTENT_W - 135 * mm, 25 * mm], repeatRows=1)
    gstyle = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.75, RULE),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i, f in enumerate(findings, start=1):
        gstyle.append(("BACKGROUND", (1, i), (1, i), SEVERITY[f.risk][1]))
    glance.setStyle(TableStyle(gstyle))
    story += [glance, Spacer(1, 8 * mm)]

    # --------------------------------------------------------- by severity
    for risk in RISK_ORDER:
        group = [f for f in findings if f.risk == risk]
        if not group:
            continue
        label_text, color, _bg = SEVERITY[risk]
        heading = Table(
            [[Paragraph(_safe(f"{label_text} - {len(group)} issue{'s' if len(group) != 1 else ''}"), S["section"])]],
            colWidths=[CONTENT_W],
        )
        heading.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ]))
        # Keep the heading with the first card.
        location = None if is_workflow else f"File: {name}"
        story.append(KeepTogether([heading, Spacer(1, 3 * mm), _card(group[0], number[id(group[0])], include_secrets, location)]))
        story.append(Spacer(1, 4 * mm))
        for f in group[1:]:
            story += [_card(f, number[id(f)], include_secrets, location), Spacer(1, 4 * mm)]
        story.append(Spacer(1, 3 * mm))

    story.append(Paragraph(
        ("Line numbers refer to the workflow as formatted in the scanner editor (2-space indentation). " if is_workflow
         else "Line numbers refer to the scanned file. ")
        + ("This report contains exposed secret values: share it only with people allowed to see them, and rotate those secrets."
           if include_secrets else "Secret values are not included in this report."),
        S["small"],
    ))
    return _render(story, name, scanned_at)


def _card(f: Finding, n: int, include_secrets: bool, location: str | None = None) -> Table:
    """One finding. A single-row Table never splits across pages."""
    label, color, _bg = SEVERITY[f.risk]
    inner_w = CONTENT_W - 4 * mm  # minus the coloured stripe

    badge = Table([[Paragraph(label.upper(), S["badge"])]], colWidths=[20 * mm])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
    ]))
    head = Table(
        [[badge, Paragraph(_safe(f"{n}. {f.title}"), S["card_title"]), Paragraph(_safe(_lines(f)), _style("ln", parent=S["card_line"], textColor=color))]],
        colWidths=[23 * mm, inner_w - 23 * mm - 30 * mm - 8 * mm, 30 * mm],
    )
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))

    rows: list = [
        [head],
        [Paragraph(_safe(location or f"Node: {_node(f)}"), S["small"])],
        [Paragraph("IN BRIEF", S["label"])],
        [Paragraph(_safe(f.brief), S["brief"])],
    ]
    if include_secrets and f.exposed_value:
        rows.append([_boxed("EXPOSED VALUE", f.exposed_value, S["secret_label"], S["secret"], SECRET_BG, SECRET_BORDER, inner_w - 8 * mm)])
    rows.append([_boxed("HOW TO FIX", f.remediation, S["fix_label"], S["fix"], FIX_BG, FIX_BORDER, inner_w - 8 * mm)])

    body = Table(rows, colWidths=[inner_w - 8 * mm])
    body.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (0, 0), 3), ("TOPPADDING", (0, 2), (0, 2), 6),
        ("TOPPADDING", (0, 4), (0, -1), 6),
    ]))

    card = Table([["", body]], colWidths=[4 * mm, inner_w])
    card.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), color),
        ("BOX", (0, 0), (-1, -1), 0.75, RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (1, 0), (1, 0), 4 * mm), ("RIGHTPADDING", (1, 0), (1, 0), 4 * mm),
        ("TOPPADDING", (1, 0), (1, 0), 3.5 * mm), ("BOTTOMPADDING", (1, 0), (1, 0), 3.5 * mm),
    ]))
    return card


def _boxed(label: str, text: str, label_style, text_style, bg, border, width) -> Table:
    box = Table([[Paragraph(label, label_style)], [Paragraph(_safe(text), text_style)]], colWidths=[width])
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg), ("BOX", (0, 0), (-1, -1), 0.75, border),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 6), ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
        ("TOPPADDING", (0, 1), (-1, 1), 2), ("BOTTOMPADDING", (0, 0), (-1, 0), 0),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    return box


def _render(story: list, workflow_name: str, scanned_at: datetime) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN, bottomMargin=MARGIN,
        title=f"Security report - {workflow_name}", author="Workflow & Code Security Scanner",
        subject="Security findings",
    )
    header = _plain(f"Security report - {workflow_name}")[:110]
    generated = f"Generated by Workflow & Code Security Scanner · {scanned_at.strftime('%d %b %Y')}"
    doc.build(story, canvasmaker=lambda *a, **kw: _NumberedCanvas(*a, header=header, generated=generated, **kw))
    return buffer.getvalue()
