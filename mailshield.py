#!/usr/bin/env python3
"""
MailShield Auditor
Built by Rajveer Singh / TechExon

A lightweight email security auditing tool for SPF, DKIM, DMARC, MX,
and spoofing-risk assessment.

For defensive and authorized domain security audits only.
"""

import dns.resolver
import sys
import os
import re
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "zoho", "zmail", "mail", "dkim", "smtp",
    "k1", "s1", "s2", "mandrill", "sendgrid",
    "mailgun", "pm", "protonmail", "mxvault"
]

def clean_domain(domain):
    domain = domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0]
    domain = domain.replace("www.", "")
    return domain

def get_txt_records(name):
    try:
        answers = dns.resolver.resolve(name, "TXT")
        records = []
        for rdata in answers:
            txt = "".join([
                part.decode() if isinstance(part, bytes) else str(part)
                for part in rdata.strings
            ])
            records.append(txt)
        return records
    except Exception:
        return []

def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = []
        for r in answers:
            mx_records.append({
                "priority": r.preference,
                "host": str(r.exchange).rstrip(".")
            })
        return sorted(mx_records, key=lambda x: x["priority"])
    except Exception:
        return []

def check_spf(domain):
    txt_records = get_txt_records(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]
    findings = []
    score = 25

    if not spf_records:
        return {
            "status": "MISSING",
            "records": [],
            "score": 0,
            "findings": ["No SPF record found."],
            "recommendation": "Add an SPF record that authorizes your real mail provider only."
        }

    if len(spf_records) > 1:
        score -= 15
        findings.append("Multiple SPF records found. This can break SPF validation.")

    spf = spf_records[0]

    include_count = spf.count("include:")
    if include_count > 8:
        score -= 10
        findings.append("SPF has many include mechanisms. This may approach the DNS lookup limit.")

    if "+all" in spf:
        score = 0
        findings.append("SPF uses +all. This allows any server to send email for this domain.")
    elif "~all" in spf:
        score -= 10
        findings.append("SPF uses softfail ~all. This is weaker than strict -all.")
    elif "?all" in spf:
        score -= 15
        findings.append("SPF uses neutral ?all. This gives weak protection.")
    elif "-all" in spf:
        findings.append("SPF uses strict -all. This is good.")
    else:
        score -= 8
        findings.append("SPF record does not clearly end with -all, ~all, ?all, or +all.")

    if "include:zoho.in" in spf or "include:zoho.com" in spf:
        findings.append("Zoho mail provider detected.")

    score = max(score, 0)

    rec = "Use strict SPF after confirming all legitimate senders: v=spf1 include:YOUR_PROVIDER -all"
    if "zoho" in spf:
        rec = "Recommended SPF for Zoho-only sending: v=spf1 include:zoho.in -all"

    return {
        "status": "FOUND",
        "records": spf_records,
        "score": score,
        "findings": findings,
        "recommendation": rec
    }

def parse_dmarc_tags(record):
    tags = {}
    parts = record.split(";")
    for part in parts:
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags

def check_dmarc(domain):
    records = get_txt_records(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]
    findings = []
    score = 35

    if not dmarc_records:
        return {
            "status": "MISSING",
            "records": [],
            "score": 0,
            "tags": {},
            "findings": ["No DMARC record found."],
            "recommendation": "Add DMARC. Start with monitoring, then move to quarantine/reject."
        }

    if len(dmarc_records) > 1:
        score -= 15
        findings.append("Multiple DMARC records found. This can break DMARC validation.")

    dmarc = dmarc_records[0]
    tags = parse_dmarc_tags(dmarc)

    policy = tags.get("p", "").lower()
    sub_policy = tags.get("sp", "").lower()
    pct = tags.get("pct", "100")
    rua = tags.get("rua", "")
    adkim = tags.get("adkim", "r")
    aspf = tags.get("aspf", "r")

    if policy == "none":
        score -= 22
        findings.append("DMARC policy is p=none. It monitors only and does not block spoofing.")
    elif policy == "quarantine":
        score -= 8
        findings.append("DMARC policy is quarantine. Suspicious emails may go to spam.")
    elif policy == "reject":
        findings.append("DMARC policy is reject. This is strongest.")
    else:
        score -= 20
        findings.append("DMARC policy is missing or invalid.")

    if not rua:
        score -= 5
        findings.append("DMARC aggregate reporting address rua is missing.")
    else:
        findings.append("DMARC aggregate reporting is enabled.")

    try:
        pct_int = int(pct)
        if pct_int < 100:
            score -= 5
            findings.append(f"DMARC pct is {pct_int}. Policy is not applied to all mail.")
    except Exception:
        score -= 3
        findings.append("DMARC pct value is invalid.")

    if not sub_policy:
        score -= 3
        findings.append("DMARC subdomain policy sp is missing.")
    else:
        findings.append(f"DMARC subdomain policy detected: sp={sub_policy}")

    if adkim == "s":
        findings.append("DKIM alignment is strict.")
    else:
        findings.append("DKIM alignment is relaxed.")

    if aspf == "s":
        findings.append("SPF alignment is strict.")
    else:
        findings.append("SPF alignment is relaxed.")

    score = max(score, 0)

    return {
        "status": "FOUND",
        "records": dmarc_records,
        "score": score,
        "tags": tags,
        "findings": findings,
        "recommendation": "Recommended path: p=none → p=quarantine → p=reject after confirming SPF/DKIM alignment."
    }

def check_dkim(domain):
    found = []
    for selector in COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        records = get_txt_records(name)
        for record in records:
            if "v=DKIM1" in record or "p=" in record:
                preview = record[:180] + "..." if len(record) > 180 else record
                found.append({
                    "selector": selector,
                    "record": preview
                })

    if found:
        score = 25
        status = "FOUND"
        findings = [f"DKIM selector found: {item['selector']}" for item in found]
        recommendation = "DKIM is detected using common selectors. Confirm it is enabled in your mail provider."
    else:
        score = 5
        status = "NOT FOUND"
        findings = ["No DKIM record found using common selectors. Manual provider verification may still be required."]
        recommendation = "Enable DKIM in your mail provider admin panel and add the provided DNS TXT record."

    return {
        "status": status,
        "records": found,
        "score": score,
        "findings": findings,
        "recommendation": recommendation
    }

def check_mx(domain):
    mx = get_mx_records(domain)
    if mx:
        providers = []
        for item in mx:
            host = item["host"].lower()
            if "zoho" in host:
                providers.append("Zoho")
            elif "google" in host or "aspmx" in host:
                providers.append("Google Workspace")
            elif "outlook" in host or "protection.outlook" in host:
                providers.append("Microsoft 365")
            elif "proton" in host:
                providers.append("Proton Mail")

        provider_text = ", ".join(sorted(set(providers))) if providers else "Unknown provider"

        return {
            "status": "FOUND",
            "records": mx,
            "score": 10,
            "provider": provider_text,
            "findings": [f"Mail exchange is configured. Provider hint: {provider_text}"],
            "recommendation": "MX records are present. Confirm they match the intended mail provider."
        }

    return {
        "status": "MISSING",
        "records": [],
        "score": 0,
        "provider": "None",
        "findings": ["No MX records found."],
        "recommendation": "Add MX records for your email provider if this domain sends or receives business email."
    }

def calculate_grade(total_score):
    if total_score >= 90:
        return "A+"
    if total_score >= 80:
        return "A"
    if total_score >= 70:
        return "B"
    if total_score >= 55:
        return "C"
    if total_score >= 40:
        return "D"
    return "F"

def calculate_risk(total_score):
    if total_score >= 75:
        return "LOW"
    if total_score >= 50:
        return "MEDIUM"
    return "HIGH"

def business_impact(risk):
    if risk == "HIGH":
        return (
            "This domain has weak email authentication. Attackers may be able to impersonate "
            "the business in phishing emails, fake invoices, password reset messages, or payment change requests."
        )
    if risk == "MEDIUM":
        return (
            "This domain has partial email protection, but policy weaknesses may still allow spoofed emails "
            "to reach customers or employees in some cases."
        )
    return (
        "This domain has strong baseline protection against email spoofing. Continued monitoring is recommended."
    )

def generate_text_report(domain, result, report_dir):
    path = os.path.join(report_dir, "report.txt")
    with open(path, "w") as f:
        f.write("TechExon MailShield Auditor\n")
        f.write("=" * 40 + "\n")
        f.write(f"Domain: {domain}\n")
        f.write(f"Generated: {result['generated_at']}\n")
        f.write(f"Grade: {result['grade']}\n")
        f.write(f"Score: {result['score']}/100\n")
        f.write(f"Risk: {result['risk']}\n\n")

        f.write("Business Impact\n")
        f.write("-" * 40 + "\n")
        f.write(result["business_impact"] + "\n\n")

        for section in ["mx", "spf", "dmarc", "dkim"]:
            data = result[section]
            f.write(section.upper() + "\n")
            f.write("-" * 40 + "\n")
            f.write(f"Status: {data['status']}\n")
            f.write(f"Score: {data['score']}\n")
            f.write("Findings:\n")
            for item in data["findings"]:
                f.write(f"- {item}\n")
            f.write(f"Recommendation: {data['recommendation']}\n\n")

    return path

def html_escape(text):
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

def generate_html_report(domain, result, report_dir):
    path = os.path.join(report_dir, "report.html")

    risk_class = result["risk"].lower()
    sections_html = ""

    for key, title in [
        ("mx", "MX Records"),
        ("spf", "SPF Authentication"),
        ("dmarc", "DMARC Policy"),
        ("dkim", "DKIM Detection")
    ]:
        data = result[key]
        findings = "".join([f"<li>{html_escape(x)}</li>" for x in data["findings"]])

        raw_records = ""
        if data["records"]:
            raw_records += "<pre>"
            for record in data["records"]:
                raw_records += html_escape(record) + "\n"
            raw_records += "</pre>"
        else:
            raw_records = "<p class='muted'>No records found.</p>"

        sections_html += f"""
        <div class="card">
            <div class="card-header">
                <h2>{title}</h2>
                <span class="status">{data['status']}</span>
            </div>
            <p><strong>Score:</strong> {data['score']}</p>
            <h3>Findings</h3>
            <ul>{findings}</ul>
            <h3>Recommendation</h3>
            <p>{html_escape(data['recommendation'])}</p>
            <h3>Raw DNS Evidence</h3>
            {raw_records}
        </div>
        """

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>TechExon MailShield Report - {html_escape(domain)}</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            background: #0b1020;
            color: #e8ecf3;
            font-family: Arial, sans-serif;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 20px;
        }}
        .hero {{
            background: linear-gradient(135deg, #111936, #172554);
            border: 1px solid #26345f;
            border-radius: 18px;
            padding: 32px;
            margin-bottom: 24px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.35);
        }}
        .brand {{
            color: #67e8f9;
            font-size: 14px;
            letter-spacing: 2px;
            text-transform: uppercase;
            font-weight: bold;
        }}
        h1 {{
            margin: 10px 0;
            font-size: 34px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 14px;
            margin-top: 24px;
        }}
        .metric {{
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 14px;
            padding: 18px;
        }}
        .metric small {{
            color: #94a3b8;
            display: block;
            margin-bottom: 8px;
        }}
        .metric strong {{
            font-size: 24px;
        }}
        .risk.low strong {{ color: #22c55e; }}
        .risk.medium strong {{ color: #facc15; }}
        .risk.high strong {{ color: #ef4444; }}
        .card {{
            background: #111827;
            border: 1px solid #263244;
            border-radius: 18px;
            padding: 24px;
            margin-bottom: 18px;
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
        }}
        .card h2 {{
            margin: 0;
            color: #93c5fd;
        }}
        .card h3 {{
            margin-bottom: 8px;
            color: #cbd5e1;
        }}
        .status {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 999px;
            padding: 8px 12px;
            font-size: 12px;
            font-weight: bold;
        }}
        .impact {{
            background: #171717;
            border-left: 5px solid #67e8f9;
            border-radius: 14px;
            padding: 22px;
            margin-bottom: 18px;
        }}
        pre {{
            background: #020617;
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 14px;
            overflow-x: auto;
            color: #bae6fd;
        }}
        .muted {{
            color: #94a3b8;
        }}
        .footer {{
            color: #94a3b8;
            text-align: center;
            padding: 24px;
            font-size: 13px;
        }}
        @media (max-width: 800px) {{
            .summary-grid {{
                grid-template-columns: 1fr 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <div class="brand">TechExon MailShield Auditor</div>
            <h1>Email Spoofing Protection Report</h1>
            <p class="muted">Domain: <strong>{html_escape(domain)}</strong></p>
            <p class="muted">Generated: {html_escape(result['generated_at'])}</p>

            <div class="summary-grid">
                <div class="metric">
                    <small>Grade</small>
                    <strong>{result['grade']}</strong>
                </div>
                <div class="metric">
                    <small>Score</small>
                    <strong>{result['score']}/100</strong>
                </div>
                <div class="metric risk {risk_class}">
                    <small>Risk</small>
                    <strong>{result['risk']}</strong>
                </div>
                <div class="metric">
                    <small>Mail Provider</small>
                    <strong>{html_escape(result['mx'].get('provider', 'Unknown'))}</strong>
                </div>
            </div>
        </div>

        <div class="impact">
            <h2>Business Impact</h2>
            <p>{html_escape(result['business_impact'])}</p>
        </div>

        {sections_html}

        <div class="footer">
            Generated by TechExon MailShield Auditor — Defensive Email Security Assessment
        </div>
    </div>
</body>
</html>
"""
    with open(path, "w") as f:
        f.write(html)

    return path

def audit_domain(domain):
    mx = check_mx(domain)
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)

    total_score = mx["score"] + spf["score"] + dmarc["score"] + dkim["score"]
    grade = calculate_grade(total_score)
    risk = calculate_risk(total_score)

    result = {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "score": total_score,
        "grade": grade,
        "risk": risk,
        "business_impact": business_impact(risk),
        "mx": mx,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim
    }

    report_dir = os.path.join("reports", domain)
    os.makedirs(report_dir, exist_ok=True)

    txt_path = generate_text_report(domain, result, report_dir)
    html_path = generate_html_report(domain, result, report_dir)

    result["txt_report"] = txt_path
    result["html_report"] = html_path

    return result

def print_result(result):
    domain = result["domain"]

    console.print(Panel.fit(
        f"[bold cyan]TechExon MailShield Auditor[/bold cyan]\n"
        f"Domain: {domain}\n"
        f"Grade: {result['grade']}\n"
        f"Score: {result['score']}/100\n"
        f"Risk: {result['risk']}"
    ))

    table = Table(title="Email Security Check")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Score")
    table.add_column("Details")

    for key, title in [
        ("mx", "MX Records"),
        ("spf", "SPF"),
        ("dmarc", "DMARC"),
        ("dkim", "DKIM")
    ]:
        data = result[key]
        details = []

        if data.get("records"):
            for record in data["records"]:
                if isinstance(record, dict):
                    if "host" in record:
                        details.append(f"{record.get('priority', '')} {record.get('host', '')}".strip())
                    elif "selector" in record:
                        details.append(f"{record.get('selector')}: {record.get('record')}")
                    else:
                        details.append(str(record))
                else:
                    details.append(str(record))
        else:
            details.append("No raw record found")

        if data.get("findings"):
            details.append("")
            details.append("Finding: " + data["findings"][0])

        table.add_row(
            title,
            data["status"],
            str(data["score"]),
            "\n".join(details)
        )

    console.print(table)

    risk_color = "green"
    if result["risk"] == "HIGH":
        risk_color = "red"
    elif result["risk"] == "MEDIUM":
        risk_color = "yellow"

    console.print(Panel.fit(
        f"[bold {risk_color}]Risk Level: {result['risk']}[/bold {risk_color}]\n"
        f"Grade: {result['grade']}\n"
        f"Score: {result['score']}/100\n\n"
        f"{result['business_impact']}",
        title="Business Summary"
    ))

    console.print("\n[bold]Reports Generated:[/bold]")
    console.print(f"- TXT:  {result['txt_report']}")
    console.print(f"- HTML: {result['html_report']}")

def main():
    if len(sys.argv) != 2:
        console.print("[red]Usage:[/red] python mailshield.py example.com")
        sys.exit(1)

    domain = clean_domain(sys.argv[1])

    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain):
        console.print("[red]Invalid domain format.[/red]")
        sys.exit(1)

    result = audit_domain(domain)
    print_result(result)

if __name__ == "__main__":
    main()
