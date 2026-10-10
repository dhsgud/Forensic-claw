"""Offline HTML and PDF exports from the same checked report."""

from __future__ import annotations

import html
import re
from pathlib import Path

from forensic_claw.forensics.report.models import GeneratedReport


def _blocks(markdown: str):
    rows = []
    for line in markdown.splitlines():
        if line.startswith("|"):
            if re.fullmatch(r"[|\s:-]+", line):
                continue
            rows.append(
                [cell.strip().replace(r"\|", "|") for cell in re.split(r"(?<!\\)\|", line)[1:-1]]
            )
        else:
            if rows:
                yield "table", rows
                rows = []
            if line.strip():
                yield "text", line
    if rows:
        yield "table", rows


def _inline(text: str) -> str:
    escaped = html.escape(text)
    return re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", escaped)


def render_html(report: GeneratedReport) -> str:
    pieces = [
        f"<h1>{html.escape(report.title)}</h1>",
        "<p>검토용 초안 · 자동 분석 결과는 수사관의 확인과 서명이 필요합니다.</p>",
        f"<p>사건: {html.escape(report.case_id)} · 작성: {html.escape(report.generated_at)}</p>",
    ]
    for section in report.sections:
        pieces.append(f"<h2>{html.escape(section.title)}</h2>")
        for kind, block in _blocks(section.markdown):
            if kind == "table":
                pieces.append("<table>")
                for index, row in enumerate(block):
                    tag = "th" if index == 0 else "td"
                    pieces.append(
                        "<tr>"
                        + "".join(f"<{tag}>{_inline(cell)}</{tag}>" for cell in row)
                        + "</tr>"
                    )
                pieces.append("</table>")
            else:
                pieces.append(f"<p>{_inline(block)}</p>")
    return (
        '<!doctype html><html lang="ko"><meta charset="utf-8">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{html.escape(report.title)}</title><style>"
        "body{font:11pt 'Malgun Gothic',sans-serif;max-width:960px;margin:32px auto;padding:0 20px;color:#202833}"
        "h1{font-size:22pt}h2{font-size:15pt;border-bottom:1px solid #aaa;padding-bottom:8px}"
        "p,td,th{overflow-wrap:anywhere}table{border-collapse:collapse;width:100%;font-size:9pt}"
        "td,th{border:1px solid #aaa;padding:7px;vertical-align:top}th{background:#eef1f5}"
        "@page{size:A4;margin:18mm}@media print{body{margin:0;max-width:none;padding:0}tr{break-inside:avoid}h2{break-after:avoid}}"
        "</style><body>" + "\n".join(pieces) + "</body></html>"
    )


def render_pdf(report: GeneratedReport, path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle

    font = "ForensicKorean"
    if font not in pdfmetrics.getRegisteredFontNames():
        candidates = [
            Path("C:/Windows/Fonts/malgun.ttf"),
            Path("/usr/share/fonts/truetype/noto/NotoSansKR-Regular.ttf"),
        ]
        local_font = next((file for file in candidates if file.is_file()), None)
        if local_font:
            pdfmetrics.registerFont(TTFont(font, str(local_font)))
        else:
            font = "HYSMyeongJo-Medium"
            if font not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(UnicodeCIDFont(font))
    body = ParagraphStyle(
        "body", fontName=font, fontSize=9, leading=14, wordWrap="CJK", spaceAfter=6
    )
    cell = ParagraphStyle("cell", parent=body, fontSize=7, leading=11, spaceAfter=0)
    title = ParagraphStyle("title", parent=body, fontSize=19, leading=26, spaceAfter=14)
    heading = ParagraphStyle(
        "heading",
        parent=body,
        fontSize=13,
        leading=20,
        spaceBefore=12,
        spaceAfter=8,
        keepWithNext=True,
    )
    story = [
        Paragraph(html.escape(report.title), title),
        Paragraph("검토용 초안 - 수사관의 확인과 서명이 필요합니다.", body),
        Paragraph(html.escape(f"사건: {report.case_id} / 작성: {report.generated_at}"), body),
    ]
    for section in report.sections:
        story.append(Paragraph(html.escape(section.title), heading))
        for kind, block in _blocks(section.markdown):
            if kind == "table":
                width = (A4[0] - 36 * mm) / len(block[0])
                table = LongTable(
                    [[Paragraph(_inline(value), cell) for value in row] for row in block],
                    colWidths=[width] * len(block[0]),
                    repeatRows=1,
                    hAlign="LEFT",
                )
                table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5")),
                            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("LEFTPADDING", (0, 0), (-1, -1), 5),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                        ]
                    )
                )
                story.extend([table, Spacer(1, 8)])
            else:
                story.append(Paragraph(_inline(block), body))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(font, 8)
        canvas.drawString(18 * mm, 12 * mm, "Forensic-Claw / 검토용 초안")
        canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, str(doc.page))
        canvas.restoreState()

    SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title=report.title,
    ).build(story, onFirstPage=footer, onLaterPages=footer)
