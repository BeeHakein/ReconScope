"""
Report export endpoints for ReconScope.

Provides JSON, CSV, and PDF export of scan results as downloadable files.
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db_session
from app.models.scan import Scan
from app.models.subdomain import Subdomain
from app.models.service import Service
from app.models.technology import Technology
from app.models.cve import CVEMatch
from app.models.finding import Finding
from app.models.attack_path import AttackPath
from app.models.correlation import Correlation

logger = logging.getLogger(__name__)
router = APIRouter()


async def _load_scan_full(db: AsyncSession, scan_id: UUID) -> Scan:
    """Load a scan with all relationships eagerly loaded."""
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.subdomains)
            .selectinload(Subdomain.services)
            .selectinload(Service.technologies),
            selectinload(Scan.subdomains)
            .selectinload(Subdomain.services)
            .selectinload(Service.cves),
            selectinload(Scan.findings),
            selectinload(Scan.attack_paths),
            selectinload(Scan.correlations),
        )
        .where(Scan.id == scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )
    return scan


def _scan_to_dict(scan: Scan) -> dict[str, Any]:
    """Serialize a scan and its relationships to a plain dict."""
    subdomains = []
    for sub in scan.subdomains:
        services = []
        for svc in sub.services:
            techs = [
                {
                    "name": t.name,
                    "version": t.version,
                    "category": t.category,
                    "confidence": t.confidence,
                }
                for t in svc.technologies
            ]
            cves = [
                {
                    "cve_id": c.cve_id,
                    "cvss_score": c.cvss_score,
                    "severity": c.severity,
                    "description": c.description,
                    "epss_score": getattr(c, "epss_score", None),
                    "epss_percentile": getattr(c, "epss_percentile", None),
                }
                for c in svc.cves
            ]
            services.append({
                "port": svc.port,
                "protocol": svc.protocol,
                "service_name": svc.service_name,
                "version": svc.version,
                "technologies": techs,
                "cves": cves,
            })
        subdomains.append({
            "name": sub.name,
            "ip_address": sub.ip_address,
            "source": sub.source,
            "is_alive": sub.is_alive,
            "services": services,
        })

    findings = [
        {
            "title": f.title,
            "severity": f.severity,
            "description": f.description,
            "asset": f.asset,
            "risk_score": f.risk_score,
            "cvss_score": f.cvss_score,
        }
        for f in scan.findings
    ]

    attack_paths = [
        {
            "title": ap.title,
            "severity": ap.severity,
            "steps": ap.steps,
        }
        for ap in scan.attack_paths
    ]

    correlations = [
        {
            "type": c.correlation_type,
            "severity": c.severity,
            "message": c.message,
        }
        for c in scan.correlations
    ]

    return {
        "scan_id": str(scan.id),
        "target": scan.target.domain if scan.target else "unknown",
        "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "overall_risk": scan.overall_risk,
        "total_subdomains": scan.total_subdomains,
        "total_services": scan.total_services,
        "total_cves": scan.total_cves,
        "subdomains": subdomains,
        "findings": findings,
        "attack_paths": attack_paths,
        "correlations": correlations,
    }


# -- JSON export ---------------------------------------------------------------

@router.get("/{scan_id}/export/json")
async def export_json(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> StreamingResponse:
    """Export full scan results as a JSON file download."""
    import json

    scan = await _load_scan_full(db, scan_id)
    data = _scan_to_dict(scan)
    content = json.dumps(data, indent=2, default=str)
    target = data.get("target", "scan")

    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="reconscope_{target}_{scan_id}.json"',
        },
    )


# -- CSV export ----------------------------------------------------------------

@router.get("/{scan_id}/export/csv")
async def export_csv(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> StreamingResponse:
    """Export findings as a CSV file download."""
    scan = await _load_scan_full(db, scan_id)
    data = _scan_to_dict(scan)
    target = data.get("target", "scan")

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Type", "Severity", "Title/Message", "Asset", "Risk Score",
        "CVSS Score", "Description",
    ])

    # Findings
    for f in data.get("findings", []):
        writer.writerow([
            "Finding",
            f.get("severity", ""),
            f.get("title", ""),
            f.get("asset", ""),
            f.get("risk_score", ""),
            f.get("cvss_score", ""),
            f.get("description", ""),
        ])

    # CVEs from subdomains
    for sub in data.get("subdomains", []):
        for svc in sub.get("services", []):
            for cve in svc.get("cves", []):
                writer.writerow([
                    "CVE",
                    cve.get("severity", ""),
                    cve.get("cve_id", ""),
                    f"{sub['name']}:{svc['port']}",
                    "",
                    cve.get("cvss_score", ""),
                    (cve.get("description", "") or "")[:200],
                ])

    # Correlations
    for c in data.get("correlations", []):
        writer.writerow([
            "Insight",
            c.get("severity", ""),
            c.get("message", ""),
            "",
            "",
            "",
            "",
        ])

    # Attack paths
    for ap in data.get("attack_paths", []):
        writer.writerow([
            "Attack Path",
            ap.get("severity", ""),
            ap.get("title", ""),
            "",
            "",
            "",
            str(ap.get("steps", "")),
        ])

    csv_bytes = output.getvalue().encode("utf-8")

    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="reconscope_{target}_{scan_id}.csv"',
        },
    )


# -- PDF export ----------------------------------------------------------------

@router.get("/{scan_id}/export/pdf")
async def export_pdf(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db_session),
) -> StreamingResponse:
    """Export scan summary as a PDF file download.

    Uses reportlab if available, otherwise falls back to a simple
    text-based PDF.
    """
    scan = await _load_scan_full(db, scan_id)
    data = _scan_to_dict(scan)
    target = data.get("target", "scan")

    try:
        pdf_bytes = _generate_pdf_reportlab(data)
    except ImportError:
        pdf_bytes = _generate_pdf_simple(data)

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="reconscope_{target}_{scan_id}.pdf"',
        },
    )


def _generate_pdf_reportlab(data: dict[str, Any]) -> bytes:
    """Generate a PDF using reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#0891b2")
    )
    elements.append(Paragraph(f"ReconScope Report: {data.get('target', 'N/A')}", title_style))
    elements.append(Spacer(1, 10))

    # Summary
    summary_data = [
        ["Target", data.get("target", "N/A")],
        ["Status", data.get("status", "N/A")],
        ["Overall Risk", (data.get("overall_risk") or "N/A").upper()],
        ["Subdomains", str(data.get("total_subdomains", 0))],
        ["Services", str(data.get("total_services", 0))],
        ["CVEs", str(data.get("total_cves", 0))],
        ["Scan Date", data.get("created_at", "N/A")],
    ]
    t = Table(summary_data, colWidths=[120, 350])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#334155")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 15))

    # Findings table
    findings = data.get("findings", [])
    if findings:
        elements.append(Paragraph("Findings", styles["Heading2"]))
        findings_header = ["Severity", "Title", "Asset", "CVSS"]
        findings_rows = [findings_header]
        for f in findings[:50]:  # Limit to 50 rows for PDF
            findings_rows.append([
                (f.get("severity") or "").upper(),
                (f.get("title") or "")[:60],
                (f.get("asset") or "")[:40],
                str(f.get("cvss_score") or "N/A"),
            ])

        ft = Table(findings_rows, colWidths=[70, 220, 130, 50])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(ft)
        elements.append(Spacer(1, 15))

    # Correlations / Insights
    correlations = data.get("correlations", [])
    if correlations:
        elements.append(Paragraph("Insights", styles["Heading2"]))
        for c in correlations[:20]:
            sev = (c.get("severity") or "info").upper()
            msg = c.get("message", "")
            elements.append(Paragraph(f"<b>[{sev}]</b> {msg}", styles["Normal"]))
            elements.append(Spacer(1, 4))
        elements.append(Spacer(1, 10))

    # Attack Paths
    attack_paths = data.get("attack_paths", [])
    if attack_paths:
        elements.append(Paragraph("Attack Paths", styles["Heading2"]))
        for ap in attack_paths[:10]:
            risk = (ap.get("risk_level") or "info").upper()
            name = ap.get("title", "")
            desc = (ap.get("description") or "")[:200]
            elements.append(Paragraph(f"<b>[{risk}] {name}</b>", styles["Normal"]))
            if desc:
                elements.append(Paragraph(desc, styles["Normal"]))
            elements.append(Spacer(1, 6))

    doc.build(elements)
    return buffer.getvalue()


def _generate_pdf_simple(data: dict[str, Any]) -> bytes:
    """Generate a minimal PDF without reportlab (plain text fallback)."""
    lines = [
        f"ReconScope Scan Report",
        f"{'=' * 50}",
        f"Target: {data.get('target', 'N/A')}",
        f"Status: {data.get('status', 'N/A')}",
        f"Risk: {(data.get('overall_risk') or 'N/A').upper()}",
        f"Subdomains: {data.get('total_subdomains', 0)}",
        f"Services: {data.get('total_services', 0)}",
        f"CVEs: {data.get('total_cves', 0)}",
        f"Date: {data.get('created_at', 'N/A')}",
        "",
        "FINDINGS",
        "-" * 40,
    ]

    for f in data.get("findings", [])[:30]:
        sev = (f.get("severity") or "").upper()
        lines.append(f"[{sev}] {f.get('title', '')} - {f.get('asset', '')}")

    lines.extend(["", "INSIGHTS", "-" * 40])
    for c in data.get("correlations", []):
        sev = (c.get("severity") or "").upper()
        lines.append(f"[{sev}] {c.get('message', '')}")

    text = "\n".join(lines)

    # Minimal valid PDF with text
    content = text.encode("latin-1", errors="replace")
    stream_length = len(content)
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]"
        b"/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
        b"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Courier>>endobj\n"
        b"4 0 obj<</Length " + str(stream_length + 40).encode() + b">>\n"
        b"stream\n"
        b"BT /F1 8 Tf 40 800 Td 10 TL\n"
    )
    for line in text.split("\n"):
        safe = line.replace("(", "\\(").replace(")", "\\)")
        pdf += f"({safe}) '\n".encode("latin-1", errors="replace")
    pdf += b"ET\nendstream\nendobj\n"
    xref_offset = len(pdf)
    pdf += (
        b"xref\n0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000300 00000 n \n"
        b"0000000250 00000 n \n"
        b"trailer<</Size 6/Root 1 0 R>>\n"
        b"startxref\n"
        + str(xref_offset).encode()
        + b"\n%%EOF\n"
    )
    return pdf
