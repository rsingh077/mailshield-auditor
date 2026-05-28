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

```bash
git clone https://github.com/rsingh077/mailshield-auditor.git
cd mailshield-auditor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
