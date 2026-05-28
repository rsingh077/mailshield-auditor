# MailShield Auditor

MailShield Auditor is a lightweight email security auditing tool built by TechExon.

It checks a domain's email authentication posture and generates a simple security report for SPF, DKIM, DMARC, MX records, and spoofing-risk indicators.

## Features

- MX record check
- SPF record check
- DMARC policy check
- DKIM selector checks
- Spoofing risk indicators
- Email security score summary
- TXT/HTML report generation

## Use Cases

- Email spoofing risk audits
- Client cybersecurity reports
- SPF, DKIM, and DMARC verification
- Domain email security assessment
- Pre-sales security audit reports

## Installation

    git clone https://github.com/rsingh077/mailshield-auditor.git
    cd mailshield-auditor
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

## Usage

    python3 mailshield.py example.com

Example:

    python3 mailshield.py techexon.app

Reports are generated inside the reports/ directory.

## Sample Report

This repository includes a sample audit report generated for demonstration purposes:

- examples/sample-report.txt
- examples/sample-report.html

## Example Output

    Domain: techexon.app
    Grade: C
    Score: 55/100
    Risk: MEDIUM

The tool checks MX, SPF, DMARC, and DKIM records, then generates TXT and HTML reports.

## Disclaimer

This tool is intended for defensive security auditing and authorized domain assessments only. Do not use it on domains without permission.

## Author

Built by Rajveer Singh / TechExon.

GitHub: https://github.com/rsingh077  
Website: https://techexon.app
