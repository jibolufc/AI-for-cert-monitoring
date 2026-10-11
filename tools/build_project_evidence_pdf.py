#!/usr/bin/env python3
"""Build the combined project evidence pack as a polished PDF."""

from __future__ import annotations

from datetime import date
from html import escape
from pathlib import Path
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    ListFlowable,
    ListItem,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "pdf" / "AI_Cryptographic_Control_Plane_Project_Evidence_Pack.pdf"

SOURCE_DOCUMENTS = [
    ("Project progress summary", ROOT / "PROJECT_PROGRESS_SUMMARY.md"),
    ("Product Requirements Document", ROOT / "docs/project/01-product-requirements-document.md"),
    ("High-Level Design", ROOT / "docs/project/02-high-level-design.md"),
    ("Low-Level Design", ROOT / "docs/project/03-low-level-design.md"),
    ("Requirements Traceability Matrix", ROOT / "docs/project/04-requirements-traceability-matrix.md"),
    ("Verification and Validation Plan", ROOT / "docs/project/05-verification-and-validation-plan.md"),
    ("Security, Risk and Assurance Plan", ROOT / "docs/project/06-security-risk-and-assurance-plan.md"),
    ("Delivery Roadmap and Governance", ROOT / "docs/project/07-delivery-roadmap-and-governance.md"),
    ("Project Evidence and Demonstration Guide", ROOT / "docs/project/08-project-evidence-and-demo-guide.md"),
    ("Appendix A - ADR-001", ROOT / "docs/architecture/ADR-001-foundation-and-first-vertical-slice.md"),
    ("Appendix B - ADR-002", ROOT / "docs/architecture/ADR-002-trustworthy-intake-and-replay.md"),
    ("Appendix C - ADR-003", ROOT / "docs/architecture/ADR-003-pqc-inventory-and-exposure.md"),
    ("Appendix D - ADR-004", ROOT / "docs/architecture/ADR-004-controlled-discovery-lab.md"),
    ("Appendix E - Threat Model", ROOT / "docs/threat-model/THREAT_MODEL.md"),
    ("Appendix F - SOC Playbook", ROOT / "docs/soc-playbooks/CERT-001-unknown-domain.md"),
]

NAVY = colors.HexColor("#102A43")
BLUE = colors.HexColor("#1769AA")
TEAL = colors.HexColor("#0B7A75")
PALE_BLUE = colors.HexColor("#EAF3FA")
PALE_TEAL = colors.HexColor("#E9F6F4")
LIGHT = colors.HexColor("#F5F7FA")
MID = colors.HexColor("#BCCCDC")
TEXT = colors.HexColor("#243B53")
MUTED = colors.HexColor("#627D98")
RED = colors.HexColor("#B42318")


def ascii_text(value: str) -> str:
    replacements = {
        "\u2010": "-",
        "\u2011": "-",
        "\u2012": "-",
        "\u2013": "-",
        "\u2014": " - ",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
        "\u2192": "->",
        "\u2190": "<-",
        "\u2264": "<=",
        "\u2265": ">=",
        "\u00a0": " ",
    }
    for source, target in replacements.items():
        value = value.replace(source, target)
    return value


def inline_markup(value: str) -> str:
    value = escape(ascii_text(value.strip()))
    value = re.sub(r"`([^`]+)`", r'<font name="Courier">\1</font>', value)
    value = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", value)
    value = re.sub(r"\*([^*]+)\*", r"<i>\1</i>", value)
    value = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        r'<link href="\2" color="#1769AA">\1</link>',
        value,
    )
    value = re.sub(
        r"(?<![\"=])(https?://[^\s&lt;]+)",
        r'<link href="\1" color="#1769AA">\1</link>',
        value,
    )
    return value


def make_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "CoverTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=28, leading=34, textColor=colors.white, alignment=TA_LEFT,
            spaceAfter=12, leftIndent=32 * mm, rightIndent=20 * mm,
        ),
        "subtitle": ParagraphStyle(
            "CoverSubtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=13, leading=19, textColor=colors.HexColor("#D9EAF7"),
            leftIndent=32 * mm, rightIndent=20 * mm,
        ),
        "cover_status": ParagraphStyle(
            "CoverStatus", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=11, leading=14, textColor=colors.white, alignment=TA_CENTER,
        ),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=21, leading=25, textColor=NAVY, spaceBefore=0, spaceAfter=12,
            keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=14, leading=18, textColor=BLUE, spaceBefore=13, spaceAfter=6,
            keepWithNext=True,
        ),
        "h3": ParagraphStyle(
            "H3", parent=base["Heading3"], fontName="Helvetica-Bold",
            fontSize=11.5, leading=15, textColor=TEAL, spaceBefore=10, spaceAfter=4,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontName="Helvetica",
            fontSize=9.2, leading=13.2, textColor=TEXT, spaceAfter=6,
        ),
        "bullet": ParagraphStyle(
            "Bullet", parent=base["BodyText"], fontName="Helvetica",
            fontSize=9, leading=12.5, textColor=TEXT, leftIndent=5,
        ),
        "code": ParagraphStyle(
            "Code", parent=base["Code"], fontName="Courier", fontSize=7.5,
            leading=10, textColor=colors.HexColor("#334E68"), backColor=LIGHT,
            borderColor=MID, borderWidth=0.5, borderPadding=7, spaceBefore=4,
            spaceAfter=8,
        ),
        "small": ParagraphStyle(
            "Small", parent=base["BodyText"], fontName="Helvetica",
            fontSize=7.2, leading=9.2, textColor=TEXT,
        ),
        "table_header": ParagraphStyle(
            "TableHeader", parent=base["BodyText"], fontName="Helvetica-Bold",
            fontSize=7.1, leading=9, textColor=colors.white,
        ),
        "table_body": ParagraphStyle(
            "TableBody", parent=base["BodyText"], fontName="Helvetica",
            fontSize=6.9, leading=9, textColor=TEXT,
        ),
        "toc_h": ParagraphStyle(
            "TOCHeading", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=24, leading=28, textColor=NAVY, spaceAfter=16,
        ),
        "toc1": ParagraphStyle(
            "TOC1", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=10, leading=14, leftIndent=0, firstLineIndent=0,
            textColor=NAVY, spaceBefore=3,
        ),
        "toc2": ParagraphStyle(
            "TOC2", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=12, leftIndent=12, firstLineIndent=0,
            textColor=TEXT,
        ),
    }


STYLES = make_styles()


class EvidencePackTemplate(BaseDocTemplate):
    def __init__(self, filename: Path):
        super().__init__(
            str(filename), pagesize=A4,
            leftMargin=18 * mm, rightMargin=18 * mm,
            topMargin=21 * mm, bottomMargin=18 * mm,
            title="AI-Assisted Cryptographic Control Plane - Project Evidence Pack",
            author="Project repository",
            subject="Work-in-progress project evidence, design, assurance and roadmap",
        )
        width, height = A4
        cover_frame = Frame(0, 0, width, height, id="cover", leftPadding=0,
                            rightPadding=0, topPadding=0, bottomPadding=0)
        body_frame = Frame(
            self.leftMargin, self.bottomMargin,
            width - self.leftMargin - self.rightMargin,
            height - self.topMargin - self.bottomMargin,
            id="body",
        )
        self.addPageTemplates([
            PageTemplate(id="cover", frames=[cover_frame], onPage=self._cover_page),
            PageTemplate(id="body", frames=[body_frame], onPage=self._body_page),
        ])
        self._bookmark_id = 0

    def beforeDocument(self):
        self._bookmark_id = 0

    def _cover_page(self, canvas, doc):
        width, height = A4
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, 0, width, height, stroke=0, fill=1)
        canvas.setFillColor(BLUE)
        canvas.rect(0, 0, 16 * mm, height, stroke=0, fill=1)
        canvas.setFillColor(TEAL)
        canvas.rect(16 * mm, 0, 4 * mm, height, stroke=0, fill=1)
        canvas.restoreState()

    def _body_page(self, canvas, doc):
        width, height = A4
        canvas.saveState()
        canvas.setStrokeColor(MID)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, height - 14 * mm, width - 18 * mm, height - 14 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, height - 11 * mm, "AI-Assisted Cryptographic Control Plane")
        canvas.drawRightString(width - 18 * mm, height - 11 * mm, "WORK IN PROGRESS")
        canvas.line(18 * mm, 13 * mm, width - 18 * mm, 13 * mm)
        canvas.drawString(18 * mm, 9 * mm, "Project Evidence Pack | Version 0.4.0")
        canvas.drawRightString(width - 18 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    def afterFlowable(self, flowable):
        if not isinstance(flowable, Paragraph):
            return
        style = flowable.style.name
        if style not in {"H1", "H2", "H3"}:
            return
        level = {"H1": 0, "H2": 1, "H3": 2}[style]
        text = flowable.getPlainText()
        self._bookmark_id += 1
        key = f"heading-{self._bookmark_id}"
        self.canv.bookmarkPage(key)
        self.canv.addOutlineEntry(text, key, level=level, closed=level > 0)
        self.notify("TOCEntry", (level, text, self.page, key))


def parse_table(lines: list[str], available_width: float) -> Table:
    rows: list[list[str]] = []
    for line in lines:
        values = [value.strip() for value in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-{3,}:?", value) for value in values):
            continue
        rows.append(values)
    columns = max(len(row) for row in rows)
    rows = [row + [""] * (columns - len(row)) for row in rows]
    lengths = [max(8, max(len(row[index]) for row in rows)) for index in range(columns)]
    total = sum(lengths)
    widths = [available_width * length / total for length in lengths]
    minimum = 23 * mm if columns <= 4 else 17 * mm
    widths = [max(minimum, width) for width in widths]
    scale = available_width / sum(widths)
    widths = [width * scale for width in widths]
    data = []
    for row_index, row in enumerate(rows):
        style = STYLES["table_header"] if row_index == 0 else STYLES["table_body"]
        data.append([Paragraph(inline_markup(value), style) for value in row])
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, MID),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
    ]))
    return table


def markdown_flowables(text: str, available_width: float) -> list:
    lines = ascii_text(text).splitlines()
    output: list = []
    index = 0
    paragraph_parts: list[str] = []

    def flush_paragraph():
        if paragraph_parts:
            output.append(Paragraph(inline_markup(" ".join(paragraph_parts)), STYLES["body"]))
            paragraph_parts.clear()

    while index < len(lines):
        line = lines[index].rstrip()
        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            index += 1
            continue
        if stripped.startswith("```"):
            flush_paragraph()
            index += 1
            code_lines: list[str] = []
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            index += 1
            code = escape("\n".join(code_lines)).replace(" ", "&nbsp;").replace("\n", "<br/>")
            output.append(Paragraph(code or "&nbsp;", STYLES["code"]))
            continue
        if stripped.startswith("|") and "|" in stripped[1:]:
            flush_paragraph()
            table_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index])
                index += 1
            output.append(parse_table(table_lines, available_width))
            output.append(Spacer(1, 7))
            continue
        heading = re.match(r"^(#{1,3})\s+(.+)$", stripped)
        if heading:
            flush_paragraph()
            level = len(heading.group(1))
            output.append(Paragraph(inline_markup(heading.group(2)), STYLES[f"h{level}"]))
            if level == 1:
                output.append(HRFlowable(width="100%", thickness=1.2, color=TEAL, spaceAfter=10))
            index += 1
            continue
        if re.match(r"^[-*]\s+", stripped):
            flush_paragraph()
            items = []
            while index < len(lines) and re.match(r"^\s*[-*]\s+", lines[index]):
                item_text = re.sub(r"^\s*[-*]\s+", "", lines[index]).strip()
                items.append(ListItem(Paragraph(inline_markup(item_text), STYLES["bullet"]), leftIndent=10))
                index += 1
            output.append(KeepTogether([
                ListFlowable(items, bulletType="bullet", start="circle", leftIndent=15, bulletFontSize=6),
                Spacer(1, 4),
            ]))
            continue
        if re.match(r"^\d+\.\s+", stripped):
            flush_paragraph()
            items = []
            while index < len(lines) and re.match(r"^\s*\d+\.\s+", lines[index]):
                item_text = re.sub(r"^\s*\d+\.\s+", "", lines[index]).strip()
                items.append(ListItem(Paragraph(inline_markup(item_text), STYLES["bullet"]), leftIndent=12))
                index += 1
            output.append(KeepTogether([
                ListFlowable(items, bulletType="1", leftIndent=18, bulletFontSize=8),
                Spacer(1, 4),
            ]))
            continue
        paragraph_parts.append(stripped)
        index += 1
    flush_paragraph()
    return output


def cover_story() -> list:
    status = Table(
        [[Paragraph("WORK IN PROGRESS", STYLES["cover_status"])]],
        colWidths=[48 * mm], rowHeights=[11 * mm], hAlign="LEFT",
    )
    status.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), RED),
        ("BOX", (0, 0), (-1, -1), 0, RED),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return [
        Spacer(1, 40 * mm),
        Table([[Spacer(1, 1), status]], colWidths=[32 * mm, 48 * mm], hAlign="LEFT",
              style=[("LEFTPADDING", (0, 0), (-1, -1), 0),
                     ("RIGHTPADDING", (0, 0), (-1, -1), 0)]),
        Spacer(1, 14 * mm),
        Paragraph("AI-Assisted<br/>Cryptographic Control Plane", STYLES["title"]),
        Spacer(1, 5 * mm),
        Paragraph(
            "Project Evidence Pack<br/>Product requirements, architecture, "
            "detailed design, assurance, roadmap and reproducible evidence",
            STYLES["subtitle"],
        ),
        Spacer(1, 55 * mm),
        Paragraph(
            "Version 0.4.0<br/>Milestones 1-4 complete<br/>11 October 2026",
            STYLES["subtitle"],
        ),
        NextPageTemplate("body"),
        PageBreak(),
    ]


def build():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    doc = EvidencePackTemplate(OUTPUT)
    usable_width = A4[0] - doc.leftMargin - doc.rightMargin
    story = cover_story()

    story.append(Paragraph("Contents", STYLES["toc_h"]))
    story.append(Paragraph(
        "This combined pack records the current project position. Implemented, "
        "partial, planned and out-of-scope capabilities are deliberately separated.",
        STYLES["body"],
    ))
    story.append(Spacer(1, 8))
    toc = TableOfContents()
    toc.levelStyles = [STYLES["toc1"], STYLES["toc2"], STYLES["small"]]
    toc.dotsMinLevel = 0
    story.append(toc)
    story.append(PageBreak())

    for document_index, (_, path) in enumerate(SOURCE_DOCUMENTS):
        if not path.exists():
            raise FileNotFoundError(path)
        if document_index:
            story.append(PageBreak())
        story.extend(markdown_flowables(path.read_text(encoding="utf-8"), usable_width))

    doc.multiBuild(story)
    print(OUTPUT)


if __name__ == "__main__":
    build()
