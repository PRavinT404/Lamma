# reporting.py
import os
import time
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_report(findings):
    """Simple plain-text report for console/fallback."""
    report = "Penetration Test Report\n"
    report += "=======================\n"
    for finding in findings:
        report += f"- {finding}\n"
    return report

def generate_pdf_report(target, vulnerabilities, discovered_endpoints=None, scan_stats=None, output_path=None):
    """
    Generate an executive-ready, professional penetration testing PDF report.
    
    Args:
        target: Target URL
        vulnerabilities: List of vulnerability dicts discovered during test
        discovered_endpoints: List of discovered URLs / endpoints
        scan_stats: Dictionary with scan metrics (e.g. learning score, reward, duration)
        output_path: Optional explicit PDF file path
    Returns:
        Absolute path to generated PDF report
    """
    if not output_path:
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "reports")
        os.makedirs(reports_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(c if c.isalnum() else "_" for c in target.replace("http://", "").replace("https://", ""))[:30]
        output_path = os.path.join(reports_dir, f"pentest_report_{safe_name}_{ts}.pdf")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        leading=14,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=15
    )
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=12,
        spaceAfter=8
    )
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    code_style = ParagraphStyle(
        'CodeSnippet',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#0F172A')
    )
    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.white
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("APEX AI Automated Penetration Test Report", title_style))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: {target}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#3B82F6'), spaceAfter=15))

    # Executive Summary Card
    vuln_count = len(vulnerabilities) if vulnerabilities else 0
    risk_level = "CRITICAL" if vuln_count >= 3 else ("HIGH" if vuln_count > 0 else "LOW / CLEAN")
    risk_color = colors.HexColor('#EF4444') if vuln_count > 0 else colors.HexColor('#10B981')

    summary_data = [
        [
            Paragraph("<b>Target Host:</b>", body_style),
            Paragraph(str(target), body_style),
            Paragraph("<b>Overall Risk Level:</b>", body_style),
            Paragraph(f"<b><font color='{risk_color.hexval()}'>{risk_level}</font></b>", body_style)
        ],
        [
            Paragraph("<b>Vulnerabilities Found:</b>", body_style),
            Paragraph(f"<b>{vuln_count}</b> confirmed issue(s)", body_style),
            Paragraph("<b>Endpoints Discovered:</b>", body_style),
            Paragraph(f"{len(discovered_endpoints or [])} endpoints", body_style)
        ]
    ]

    summary_table = Table(summary_data, colWidths=[110, 160, 120, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 15))

    # Vulnerability Table
    story.append(Paragraph("Detailed Security Findings", heading_style))

    if vulnerabilities:
        col_widths = [110, 130, 80, 80, 140]
        table_rows = [[
            Paragraph("Vulnerability Type", table_header_style),
            Paragraph("Target Endpoint", table_header_style),
            Paragraph("Parameter", table_header_style),
            Paragraph("Confidence", table_header_style),
            Paragraph("Validation Technique", table_header_style)
        ]]

        for v in vulnerabilities:
            v_type = v.get('type', 'Vulnerability')
            v_url = v.get('url', target)
            v_param = v.get('parameter', 'N/A')
            v_conf = f"{v.get('confidence', 0.8):.0%}"
            v_tech = v.get('validation_method') or v.get('technique') or 'Automated Analysis'

            table_rows.append([
                Paragraph(f"<b>{v_type}</b>", body_style),
                Paragraph(v_url, body_style),
                Paragraph(f"<code>{v_param}</code>", code_style),
                Paragraph(v_conf, body_style),
                Paragraph(v_tech, body_style)
            ])

        vuln_table = Table(table_rows, colWidths=col_widths, repeatRows=1)
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(vuln_table)
        story.append(Spacer(1, 15))

        # Individual Finding Breakdown & Remediation
        story.append(Paragraph("Remediation & Technical Evidence", heading_style))
        for idx, v in enumerate(vulnerabilities, 1):
            finding_cards = []
            finding_cards.append(Paragraph(f"<b>Finding #{idx}: {v.get('type', 'Vulnerability')}</b>", ParagraphStyle('FTitle', parent=heading_style, fontSize=11, spaceBefore=4, spaceAfter=4)))
            
            payload = v.get('payload', 'Standard Injection Vector')
            details_content = [
                [Paragraph("<b>URL:</b>", body_style), Paragraph(str(v.get('url', '')), body_style)],
                [Paragraph("<b>Parameter:</b>", body_style), Paragraph(str(v.get('parameter', 'N/A')), code_style)],
                [Paragraph("<b>Payload:</b>", body_style), Paragraph(f"<code>{payload}</code>", code_style)],
                [Paragraph("<b>Validation:</b>", body_style), Paragraph(str(v.get('validation_method', 'Confirmed by scanner')), body_style)]
            ]
            
            # Remediation guidance based on vulnerability type
            v_type_lower = v.get('type', '').lower()
            if 'sql' in v_type_lower:
                remediation = "Use parameterized queries / prepared statements (e.g. ORM or PDO with placeholders). Never concatenate user input directly into SQL strings."
            elif 'xss' in v_type_lower:
                remediation = "Context-aware output encoding (e.g. htmlspecialchars / textContent). Avoid passing untrusted input into innerHTML, eval(), or document.write(). Implement strict Content Security Policy (CSP)."
            elif 'redirect' in v_type_lower:
                remediation = "Validate redirect destinations against a strict allowlist of domains or relative paths. Reject arbitrary external URLs."
            elif 'header' in v_type_lower:
                remediation = "Sanitize user inputs to strip newline characters (\r and \n) before setting HTTP response headers."
            elif 'csrf' in v_type_lower:
                remediation = "Enforce Anti-CSRF tokens for all state-changing actions and use SameSite=Strict/Lax cookies."
            else:
                remediation = "Sanitize and validate all user-supplied input on the server side prior to processing."

            details_content.append([Paragraph("<b>Remediation:</b>", body_style), Paragraph(remediation, body_style)])

            finding_table = Table(details_content, colWidths=[90, 450])
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F1F5F9')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#94A3B8')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ]))
            story.append(KeepTogether([*finding_cards, finding_table, Spacer(1, 10)]))
    else:
        story.append(Paragraph("No high-severity vulnerabilities were identified during this automated assessment.", body_style))
        story.append(Spacer(1, 10))

    # Attack Surface / Discovered Endpoints Section
    if discovered_endpoints:
        story.append(Spacer(1, 10))
        story.append(Paragraph("Discovered Attack Surface Endpoints", heading_style))
        ep_rows = []
        for ep in discovered_endpoints[:25]:
            ep_rows.append([Paragraph(str(ep), code_style)])
        
        ep_table = Table(ep_rows, colWidths=[540])
        ep_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(ep_table)

    # Build PDF Document
    doc.build(story)
    print(f"\n[REPORT] [+] Professional PDF report successfully generated at:")
    print(f"         {os.path.abspath(output_path)}")
    return os.path.abspath(output_path)
