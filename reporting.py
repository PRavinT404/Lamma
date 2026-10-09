import os
import time
import html
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def get_vulnerability_explanation(vuln_type, param="q", payload=""):
    """
    Generate deep, human-understandable explanation, root cause analysis,
    step-by-step trigger mechanism, impact assessment, and remediation for any finding.
    """
    v_type_lower = (vuln_type or "").lower()
    
    if "sql" in v_type_lower:
            sql_display_payload = payload if payload else "' OR 1=1 --"
            return {
                "title": "SQL Injection (SQLi)",
                "severity": "CRITICAL",
                "plain_description": (
                    "An attacker can manipulate backend database queries by injecting SQL syntax through untrusted input. "
                    "The web server fails to distinguish between the developer's SQL code and the user's data."
                ),
                "root_cause": (
                    "Dynamic SQL string concatenation: User input received via HTTP requests is concatenated directly "
                    "into raw SQL query strings without parameterization or prepared statements."
                ),
                "trigger_mechanism": [
                    f"1. The attacker injects SQL metacharacters (such as single quotes or boolean payloads: '{sql_display_payload}') into parameter '{param}'.",
                    "2. The server application constructs the database query by directly embedding this raw string.",
                    "3. The database engine executes the attacker's injected SQL logic, altering the intended query structure.",
                    "4. The database responds with either syntax error messages, boolean timing delays, or bypassed authentication states."
                ],
            "impact": (
                "Complete database compromise, unauthorized extraction of confidential user credentials, "
                "financial data theft, modification or deletion of sensitive tables, and potential remote code execution on the database server."
            ),
            "remediation": (
                "Use parameterized queries / prepared statements (e.g., PDO in PHP, parameterized SQL in Python DB-API, or ORMs like SQLAlchemy). "
                "Never construct SQL queries via string formatting or string concatenation."
            )
        }
    elif "dom" in v_type_lower:
        return {
            "title": "DOM-Based Cross-Site Scripting (DOM XSS)",
            "severity": "HIGH",
            "plain_description": (
                "Client-side JavaScript code takes data from a user-controllable source (like the URL query string or location hash) "
                "and writes it directly into an unsafe sink in the Document Object Model (DOM) without proper sanitization."
            ),
            "root_cause": (
                "Unsafe client-side sink usage: Client-side JavaScript reads user-controlled values from the DOM (e.g., location.search) "
                "and writes them directly into execution sinks like element.innerHTML, document.write(), eval(), or setTimeout()."
            ),
            "trigger_mechanism": [
                f"1. The victim visits a crafted link containing malicious JavaScript syntax in parameter '{param}'.",
                f"2. The client browser downloads and parses the page; client-side JavaScript reads '{param}' from the URL.",
                "3. The script assigns the raw value into a dangerous DOM property (e.g. innerHTML or eval()) without HTML escaping.",
                "4. The browser parses the injected string as live HTML/JavaScript, immediately executing the script in the victim's session context."
            ],
            "impact": (
                "The attacker can steal active session cookies and tokens (session hijacking), log victim keystrokes, "
                "perform unauthorized actions on behalf of the logged-in user, and deface the page in the victim's browser."
            ),
            "remediation": (
                "Avoid writing untrusted data directly to innerHTML. Use safe DOM APIs like element.textContent or element.innerText instead. "
                "If HTML rendering is necessary, sanitize the input using a battle-tested library like DOMPurify."
            )
        }
    elif "xss" in v_type_lower or "reflected" in v_type_lower:
            xss_display_payload = payload if payload else "<script>alert(1)</script>"
            return {
                "title": "Reflected Cross-Site Scripting (Reflected XSS)",
                "severity": "HIGH",
                "plain_description": (
                    "The web application takes user input from an HTTP request (such as a URL query parameter or form submission) "
                    "and immediately reflects it back in the HTTP response HTML without HTML encoding."
                ),
                "root_cause": (
                    "Missing contextual output encoding: The server reflects input received from the user directly into the HTML response body "
                    "without converting dangerous HTML characters (<, >, \", ', &) into their safe HTML entity representations."
                ),
                "trigger_mechanism": [
                    f"1. The attacker creates a malicious URL containing an HTML/JS payload: '{xss_display_payload}'.",
                    f"2. A user clicks the link, sending the HTTP request containing parameter '{param}' to the web server.",
                "3. The server processes the request and mirrors the unescaped parameter value directly into the HTML template.",
                "4. The victim's web browser renders the response, interprets the payload as code, and executes the injected JavaScript."
            ],
            "impact": (
                "Hijacking victim accounts by stealing cookies and session identifiers, phishing for credentials by injecting fake login prompts, "
                "and redirecting users to malicious external domains."
            ),
            "remediation": (
                "Apply strict contextual output encoding (e.g. htmlspecialchars() in PHP, Jinja2 auto-escaping in Python, or OWASP Java Encoder). "
                "Deploy a restrictive Content Security Policy (CSP) with 'unsafe-inline' disabled."
            )
        }
    elif "redirect" in v_type_lower:
        return {
            "title": "Open URL Redirection",
            "severity": "MEDIUM",
            "plain_description": (
                "The web application accepts an untrusted URL parameter and uses it to redirect the user to an arbitrary external website."
            ),
            "root_cause": (
                "Unvalidated redirect destination: The server-side redirection handler (HTTP 302/301 Location header) "
                "blindly trusts user-supplied URLs without checking against an allowlist of valid, safe destinations."
            ),
            "trigger_mechanism": [
                f"1. The attacker crafts a link using the legitimate site's domain pointing parameter '{param}' to an external attacker-controlled site.",
                "2. The victim clicks the trusted link believing they are visiting the legitimate service.",
                "3. The server sends an HTTP redirect header instructing the browser to navigate to the attacker's destination.",
                "4. The victim lands on an exact replica phishing website and is tricked into entering credentials."
            ],
            "impact": (
                "Highly effective credential phishing attacks that abuse the legitimate domain's reputation to trick users and bypass security filters."
            ),
            "remediation": (
                "Avoid user-controllable redirect parameters. If required, validate destinations against an explicit strict allowlist of authorized domain names or relative paths."
            )
        }
    elif "header" in v_type_lower or "crlf" in v_type_lower:
        return {
            "title": "HTTP Response Header Injection (CRLF Injection)",
            "severity": "MEDIUM",
            "plain_description": (
                "An attacker injects Carriage Return and Line Feed (CRLF / \\r\\n) characters into input that is reflected into HTTP response headers."
            ),
            "root_cause": (
                "Lack of newline sanitization: The server sets HTTP response headers based on untrusted user input without stripping \\r (0x0D) and \\n (0x0A)."
            ),
            "trigger_mechanism": [
                f"1. The attacker sends a request with CRLF sequences (%0d%0a) embedded in parameter '{param}'.",
                "2. The server writes the value into an HTTP response header (e.g. Set-Cookie or Location).",
                "3. The CRLF characters break the HTTP protocol header format, allowing the attacker to inject arbitrary headers or an entirely new HTTP response body.",
                "4. Downstream proxies and browsers interpret the split response, leading to HTTP Response Splitting or cache poisoning."
            ],
            "impact": (
                "Arbitrary cookie injection, cache poisoning affecting multiple users, and cross-site scripting via response body splitting."
            ),
            "remediation": (
                "Sanitize and strip all newline characters (\\r, \\n) before incorporating user input into any HTTP response headers."
            )
        }
    elif "csrf" in v_type_lower:
        return {
            "title": "Cross-Site Request Forgery (CSRF)",
            "severity": "MEDIUM",
            "plain_description": (
                "State-changing actions (like modifying account settings, resetting passwords, or deleting records) can be triggered "
                "via simple HTTP requests without requiring an unpredictable anti-CSRF token."
            ),
            "root_cause": (
                "Missing CSRF tokens & state-changing GET requests: The application performs sensitive state mutations via HTTP GET "
                "or fails to validate a unique, cryptographically random Anti-CSRF token on incoming requests."
            ),
            "trigger_mechanism": [
                "1. A logged-in victim visits an attacker's website or clicks a malicious image tag (e.g. &lt;img src='http://target/delete-account?user=victim'&gt;).",
                "2. The victim's browser automatically attaches session cookies to the cross-site request.",
                "3. The vulnerable server receives the request, sees valid authentication cookies, and executes the sensitive action.",
                "4. The action executes without the victim's explicit intention or awareness."
            ],
            "impact": (
                "Unauthorized modification of account settings, unauthorized money transfers, forced password changes, or unauthorized data deletion."
            ),
            "remediation": (
                "Never execute state-changing operations via HTTP GET. Implement robust anti-CSRF tokens (Synchronizer Token Pattern) for all POST/PUT/DELETE forms, and set SameSite=Lax or SameSite=Strict on all session cookies."
            )
        }
    else:
        return {
            "title": vuln_type or "Security Finding",
            "severity": "LOW",
            "plain_description": "A potential security anomaly or insecure configuration was identified during automated testing.",
            "root_cause": "Untrusted input processing or missing defensive controls on the affected endpoint.",
            "trigger_mechanism": [
                f"1. User input supplied in parameter '{param}' was accepted and processed.",
                "2. The server responded in an unexpected manner indicating weak input validation."
            ],
            "impact": "May lead to information disclosure or serve as a stepping stone for further exploitation.",
            "remediation": "Apply strict input validation, whitelist allowed characters, and enforce defensive HTTP headers."
        }

def generate_report(findings):
    """Plain-text report generator for console output and logging."""
    report = "========================================================\n"
    report += "         AUTOMATED PENETRATION TEST REPORT              \n"
    report += "========================================================\n\n"
    if not findings:
        report += "No vulnerabilities confirmed during this assessment.\n"
        return report

    for i, finding in enumerate(findings, 1):
        v_type = finding.get('type', 'Vulnerability')
        param = finding.get('parameter', 'N/A')
        url = finding.get('url', 'N/A')
        expl = get_vulnerability_explanation(v_type, param, finding.get('payload', ''))
        report += f"[{i}] {expl['title']} [{expl['severity']}]\n"
        report += f"    Endpoint    : {url}\n"
        report += f"    Parameter   : {param}\n"
        report += f"    Payload     : {finding.get('payload', 'N/A')}\n"
        report += f"    Root Cause  : {expl['root_cause']}\n"
        report += f"    Remediation : {expl['remediation']}\n\n"
    return report

def generate_pdf_report(target, vulnerabilities, discovered_endpoints=None, scan_stats=None, website_context=None, output_path=None):
    """
    Generate an executive-ready, highly readable, professional penetration test PDF report.
    Explains Plain-English definitions, Root Cause, Trigger Mechanisms, and Code Remediation.
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

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=12
    )
    heading_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=14,
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

    # Title & Metadata Header
    story.append(Paragraph("APEX AI Automated Penetration Test Report", title_style))
    story.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: {target}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563EB'), spaceAfter=14))

    # Executive Summary Box
    vuln_count = len(vulnerabilities) if vulnerabilities else 0
    if any("sql" in (v.get('type', '')).lower() for v in (vulnerabilities or [])):
        risk_level = "CRITICAL"
        risk_color = colors.HexColor('#DC2626')
    elif vuln_count >= 2:
        risk_level = "HIGH"
        risk_color = colors.HexColor('#EA580C')
    elif vuln_count == 1:
        risk_level = "MEDIUM"
        risk_color = colors.HexColor('#D97706')
    else:
        risk_level = "LOW / CLEAN"
        risk_color = colors.HexColor('#16A34A')

    summary_data = [
        [
            Paragraph("<b>Target Host:</b>", body_style),
            Paragraph(str(target), body_style),
            Paragraph("<b>Overall Risk Rating:</b>", body_style),
            Paragraph(f"<b><font color='{risk_color.hexval()}'>{risk_level}</font></b>", body_style)
        ],
        [
            Paragraph("<b>Confirmed Vulnerabilities:</b>", body_style),
            Paragraph(f"<b>{vuln_count}</b> security finding(s)", body_style),
            Paragraph("<b>Discovered Endpoints:</b>", body_style),
            Paragraph(f"{len(discovered_endpoints or [])} pages & endpoints", body_style)
        ]
    ]

    summary_table = Table(summary_data, colWidths=[120, 160, 120, 140])
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
    story.append(Spacer(1, 10))

    # Website Profile & DOM Understanding Section
    if website_context:
        story.append(Paragraph("Target Application Profile & Context", heading_style))
        site_type = website_context.get('site_type', 'Web Application')
        site_purpose = website_context.get('purpose', 'Dynamic Web Service')
        dom_features = website_context.get('dom_features', [])
        
        ctx_data = [
            [Paragraph("<b>Application Type:</b>", body_style), Paragraph(site_type, body_style)],
            [Paragraph("<b>Identified Purpose:</b>", body_style), Paragraph(site_purpose, body_style)],
            [Paragraph("<b>DOM Architecture:</b>", body_style), Paragraph(", ".join(dom_features) if dom_features else "Standard HTML5 DOM Structure", body_style)]
        ]
        ctx_table = Table(ctx_data, colWidths=[120, 420])
        ctx_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#EFF6FF')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#93C5FD')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#BFDBFE')),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        story.append(ctx_table)
        story.append(Spacer(1, 10))

    # Findings Table Overview
    story.append(Paragraph("Vulnerability Summary Table", heading_style))
    if vulnerabilities:
        col_widths = [130, 140, 80, 80, 110]
        table_rows = [[
            Paragraph("Vulnerability Type", table_header_style),
            Paragraph("Endpoint", table_header_style),
            Paragraph("Parameter", table_header_style),
            Paragraph("Severity", table_header_style),
            Paragraph("Confidence", table_header_style)
        ]]

        for v in vulnerabilities:
            v_type = v.get('type', 'Vulnerability')
            v_url = v.get('url', target)
            v_param = v.get('parameter', 'N/A')
            expl = get_vulnerability_explanation(v_type, v_param, v.get('payload', ''))
            v_conf = f"{v.get('confidence', 0.8):.0%}"

            sev_color = "#DC2626" if expl['severity'] in ["CRITICAL", "HIGH"] else "#D97706"
            table_rows.append([
                Paragraph(f"<b>{html.escape(expl['title'])}</b>", body_style),
                Paragraph(html.escape(v_url), body_style),
                Paragraph(f"<code>{html.escape(str(v_param))}</code>", code_style),
                Paragraph(f"<b><font color='{sev_color}'>{expl['severity']}</font></b>", body_style),
                Paragraph(v_conf, body_style)
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
        story.append(Spacer(1, 14))

        # Deep Root Cause, Trigger Mechanism & Remediation Cards
        story.append(Paragraph("In-Depth Vulnerability Analysis & Technical Remediation", heading_style))

        for idx, v in enumerate(vulnerabilities, 1):
            v_type = v.get('type', 'Vulnerability')
            param = v.get('parameter', 'N/A')
            payload = v.get('payload', '')
            expl = get_vulnerability_explanation(v_type, param, payload)

            card_title = ParagraphStyle('CardTitle', parent=heading_style, fontSize=11, spaceBefore=4, spaceAfter=4, textColor=colors.HexColor('#0F172A'))
            subhead_style = ParagraphStyle('SubHead', parent=body_style, fontName='Helvetica-Bold', textColor=colors.HexColor('#1E293B'))

            trigger_steps_html = "<br/>".join([html.escape(step) for step in expl['trigger_mechanism']])

            safe_url = html.escape(str(v.get('url', target)))
            safe_param = html.escape(str(param))
            safe_payload = html.escape(str(payload or 'Standard Injection Vector'))
            safe_desc = html.escape(str(expl['plain_description']))
            safe_cause = html.escape(str(expl['root_cause']))
            safe_impact = html.escape(str(expl['impact']))
            safe_remed = html.escape(str(expl['remediation']))

            details_data = [
                [Paragraph("<b>Finding:</b>", body_style), Paragraph(f"<b>#{idx}: {html.escape(expl['title'])} [{expl['severity']}]</b>", subhead_style)],
                [Paragraph("<b>Target URL:</b>", body_style), Paragraph(safe_url, body_style)],
                [Paragraph("<b>Parameter:</b>", body_style), Paragraph(f"<code>{safe_param}</code>", code_style)],
                [Paragraph("<b>Trigger Payload:</b>", body_style), Paragraph(f"<code>{safe_payload}</code>", code_style)],
                [Paragraph("<b>Plain Description:</b>", body_style), Paragraph(safe_desc, body_style)],
                [Paragraph("<b>Root Cause:</b>", body_style), Paragraph(f"<font color='#B91C1C'><b>{safe_cause}</b></font>", body_style)],
                [Paragraph("<b>Trigger Mechanism:</b>", body_style), Paragraph(trigger_steps_html, body_style)],
                [Paragraph("<b>Security Impact:</b>", body_style), Paragraph(safe_impact, body_style)],
                [Paragraph("<b>Remediation:</b>", body_style), Paragraph(f"<font color='#15803D'><b>{safe_remed}</b></font>", body_style)]
            ]

            card_table = Table(details_data, colWidths=[110, 430])
            card_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#94A3B8')),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('LEFTPADDING', (0,0), (-1,-1), 6),
                ('RIGHTPADDING', (0,0), (-1,-1), 6),
            ]))

            story.append(KeepTogether([
                Paragraph(f"Finding #{idx}: {expl['title']}", card_title),
                card_table,
                Spacer(1, 10)
            ]))
    else:
        story.append(Paragraph("No confirmed high-severity vulnerabilities were identified during this automated assessment.", body_style))
        story.append(Spacer(1, 10))

    # Attack Surface Endpoints
    if discovered_endpoints:
        story.append(Spacer(1, 10))
        story.append(Paragraph("Discovered Application Endpoints", heading_style))
        ep_rows = []
        for ep in discovered_endpoints[:30]:
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

    doc.build(story)
    print(f"\n[REPORT] [+] Professional PDF report successfully generated at:")
    print(f"         {os.path.abspath(output_path)}")
    return os.path.abspath(output_path)
