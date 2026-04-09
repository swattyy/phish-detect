# phish-detect

A command-line phishing email analyzer for security analysts. Feed it `.eml` files and get a structured risk assessment with actionable findings.

## Features

phish-detect inspects six categories of phishing indicators:

| Check | What it catches |
|---|---|
| **Sender spoofing** | From / Reply-To / Return-Path domain mismatches |
| **Suspicious URLs** | IP-based links, shady TLDs (`.xyz`, `.tk`, `.click`, ...), URL shorteners, brand lookalike domains |
| **Dangerous attachments** | `.exe`, `.js`, `.vbs`, `.scr`, `.bat`, `.ps1`, `.docm`, `.xlsm`, and more |
| **Urgency language** | Social-engineering keywords like "urgent", "suspended", "click here", "within 24 hours" |
| **Header analysis** | Extracts From, Reply-To, Return-Path, Received, X-Mailer, Message-ID |
| **Risk scoring** | Weighted 0-100 score with HIGH / MEDIUM / LOW verdict |

## Installation

```bash
# Clone the repo
git clone https://github.com/swatyy/phish-detect.git
cd phish-detect

# Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Analyze a single email file
python main.py samples/phishing_sample.eml

# Export results to JSON
python main.py samples/phishing_sample.eml --output report.json

# Compare with a legitimate email
python main.py samples/legitimate_sample.eml
```

## Example Output

```
┌──────────────────── phish-detect Analysis ────────────────────┐
│ Risk Score: 85/100  --  HIGH RISK - Likely Phishing           │
└───────────────────────────────────────────────────────────────┘

           Email Headers
┌────────────────┬──────────────────────────────────────────┐
│ Header         │ Value                                    │
├────────────────┼──────────────────────────────────────────┤
│ From           │ PayPal Security Team <security-alert@... │
│ Reply-To       │ attacker-collect@mail-drop.tk            │
│ Return-Path    │ <bounce@shady-mailer.click>              │
│ ...            │ ...                                      │
└────────────────┴──────────────────────────────────────────┘

              Findings
┌──────────────────────┬───────────────────────────────────────┐
│ Category             │ Detail                                │
├──────────────────────┼───────────────────────────────────────┤
│ sender_spoofing      │ From domain != Reply-To domain        │
│ sender_spoofing      │ From domain != Return-Path domain     │
│ ip_url               │ IP-based URL: http://192.168.44.3/... │
│ suspicious_tld       │ Suspicious TLD (.xyz): https://...    │
│ lookalike_domain     │ Possible lookalike for 'paypal'       │
│ urgency_keyword      │ "urgent"                              │
│ urgency_keyword      │ "suspended"                           │
│ urgency_keyword      │ "immediately"                         │
│ ...                  │ ...                                   │
└──────────────────────┴───────────────────────────────────────┘
```

## Project Structure

```
phish-detect/
  main.py                       # CLI analyzer
  requirements.txt              # Python dependencies
  samples/
    phishing_sample.eml         # Example phishing email (educational)
    legitimate_sample.eml       # Example clean email for comparison
```

## Disclaimer

This tool is intended for **educational and authorized security analysis purposes only**. The sample emails included in this repository are entirely fictitious and use reserved/example domains. Do not use this tool to craft, distribute, or facilitate phishing attacks. Always obtain proper authorization before analyzing email infrastructure that you do not own.
