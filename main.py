#!/usr/bin/env python3
"""phish-detect - Phishing email analyzer for security analysts.

Parses .eml files or raw email text, inspects headers, URLs, attachments,
and language cues, then outputs a structured risk report.
"""

from __future__ import annotations

import argparse
import email
import json
import re
import sys
from email import policy
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DANGEROUS_EXTENSIONS: set[str] = {
    ".exe", ".js", ".vbs", ".scr", ".bat", ".ps1",
    ".docm", ".xlsm", ".pptm", ".iso", ".img",
    ".hta", ".cmd", ".com", ".msi", ".jar",
}

SUSPICIOUS_TLDS: set[str] = {
    ".xyz", ".top", ".buzz", ".click", ".link", ".info",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".icu", ".work",
    ".rest", ".surf", ".cam",
}

URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

URGENCY_KEYWORDS: list[str] = [
    "urgent", "immediately", "verify your", "suspended",
    "click here", "act now", "confirm your", "unauthorized",
    "expire", "locked", "limited time", "within 24 hours",
    "failure to", "update your payment", "reset your password",
]

LOOKALIKE_TARGETS: list[str] = [
    "paypal", "apple", "microsoft", "google", "amazon",
    "netflix", "facebook", "instagram", "linkedin", "chase",
    "wellsfargo", "bankofamerica", "dropbox",
]

HEADER_KEYS: list[str] = [
    "From", "Reply-To", "Return-Path", "Received",
    "X-Mailer", "Message-ID",
]

console = Console()

# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------


def _extract_email_addr(value: str) -> str:
    """Pull the bare addr-spec from a header value like 'Name <addr>'."""
    match = re.search(r"<([^>]+)>", value)
    return match.group(1).lower().strip() if match else value.lower().strip()


def _extract_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1] if "@" in addr else addr


def check_sender_spoofing(msg: EmailMessage) -> list[dict[str, str]]:
    """Compare From, Reply-To, and Return-Path for mismatches."""
    findings: list[dict[str, str]] = []
    from_addr = _extract_email_addr(msg.get("From", ""))
    from_domain = _extract_domain(from_addr)

    for hdr in ("Reply-To", "Return-Path"):
        raw = msg.get(hdr)
        if not raw:
            continue
        other_addr = _extract_email_addr(raw)
        other_domain = _extract_domain(other_addr)
        if other_domain and from_domain and other_domain != from_domain:
            findings.append({
                "type": "sender_spoofing",
                "detail": f"From domain ({from_domain}) != {hdr} domain ({other_domain})",
            })
    return findings


def extract_urls(text: str) -> list[str]:
    """Return all URLs found in the email body."""
    return re.findall(r"https?://[^\s<>\"')\]]+", text)


def analyze_url(url: str) -> list[dict[str, str]]:
    """Flag suspicious characteristics of a single URL."""
    findings: list[dict[str, str]] = []
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    # IP-based URL
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        findings.append({"type": "ip_url", "detail": f"IP-based URL: {url}"})

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            findings.append({"type": "suspicious_tld", "detail": f"Suspicious TLD ({tld}): {url}"})
            break

    # URL shortener
    if hostname in URL_SHORTENERS:
        findings.append({"type": "url_shortener", "detail": f"URL shortener: {url}"})

    # Lookalike / typosquat domain
    for brand in LOOKALIKE_TARGETS:
        if brand in hostname and brand + "." not in hostname:
            findings.append({"type": "lookalike_domain", "detail": f"Possible lookalike for '{brand}': {url}"})
            break

    return findings


def check_attachments(msg: EmailMessage) -> list[dict[str, str]]:
    """Flag attachments with dangerous file extensions."""
    findings: list[dict[str, str]] = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        ext = Path(filename).suffix.lower()
        if ext in DANGEROUS_EXTENSIONS:
            findings.append({
                "type": "dangerous_attachment",
                "detail": f"Dangerous attachment: {filename} ({ext})",
            })
    return findings


def check_urgency(subject: str, body: str) -> list[dict[str, str]]:
    """Scan subject and body for social-engineering urgency keywords."""
    findings: list[dict[str, str]] = []
    combined = (subject + " " + body).lower()
    for kw in URGENCY_KEYWORDS:
        if kw in combined:
            findings.append({"type": "urgency_keyword", "detail": f"Urgency keyword found: \"{kw}\""})
    return findings


def _get_body_text(msg: EmailMessage) -> str:
    """Best-effort plaintext extraction from an email message."""
    body = msg.get_body(preferencelist=("plain", "html"))
    if body is not None:
        payload = body.get_content()
        return payload if isinstance(payload, str) else ""
    # Fallback: concatenate all text parts
    parts: list[str] = []
    for part in msg.walk():
        ct = part.get_content_type()
        if ct in ("text/plain", "text/html"):
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                parts.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

WEIGHTS: dict[str, int] = {
    "sender_spoofing": 25,
    "ip_url": 20,
    "suspicious_tld": 10,
    "url_shortener": 10,
    "lookalike_domain": 20,
    "dangerous_attachment": 15,
    "urgency_keyword": 5,
}


def compute_score(findings: list[dict[str, str]]) -> int:
    score = sum(WEIGHTS.get(f["type"], 5) for f in findings)
    return min(score, 100)


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def render_report(
    headers: dict[str, str | list[str]],
    findings: list[dict[str, str]],
    urls: list[str],
    score: int,
) -> None:
    """Print a rich-formatted analysis report to the console."""
    # Risk banner
    if score >= 70:
        color, verdict = "red", "HIGH RISK - Likely Phishing"
    elif score >= 40:
        color, verdict = "yellow", "MEDIUM RISK - Suspicious"
    else:
        color, verdict = "green", "LOW RISK - Appears Legitimate"

    console.print()
    console.print(Panel(
        f"[bold {color}]Risk Score: {score}/100  --  {verdict}[/]",
        title="[bold]phish-detect Analysis[/]",
        border_style=color,
    ))

    # Header table
    hdr_table = Table(title="Email Headers", show_lines=True)
    hdr_table.add_column("Header", style="cyan", min_width=14)
    hdr_table.add_column("Value", style="white")
    for key, val in headers.items():
        display = val if isinstance(val, str) else "\n".join(val)
        hdr_table.add_row(key, display)
    console.print(hdr_table)

    # URLs
    if urls:
        url_table = Table(title="Extracted URLs", show_lines=True)
        url_table.add_column("#", justify="right", style="dim")
        url_table.add_column("URL", style="blue")
        for idx, u in enumerate(urls, 1):
            url_table.add_row(str(idx), u)
        console.print(url_table)

    # Findings
    if findings:
        f_table = Table(title="Findings", show_lines=True)
        f_table.add_column("Category", style="magenta", min_width=20)
        f_table.add_column("Detail", style="white")
        for f in findings:
            f_table.add_row(f["type"], f["detail"])
        console.print(f_table)
    else:
        console.print(Panel("[green]No suspicious indicators found.[/]", title="Findings"))

    console.print()


def build_json_report(
    filepath: str,
    headers: dict[str, str | list[str]],
    findings: list[dict[str, str]],
    urls: list[str],
    score: int,
) -> dict[str, Any]:
    if score >= 70:
        verdict = "HIGH RISK"
    elif score >= 40:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"
    return {
        "file": filepath,
        "risk_score": score,
        "verdict": verdict,
        "headers": headers,
        "urls": urls,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def analyze(filepath: str, output: str | None = None) -> None:
    """Run the full analysis pipeline on a single email file."""
    path = Path(filepath)
    if not path.exists():
        console.print(f"[red]Error:[/] File not found: {filepath}")
        sys.exit(1)

    raw = path.read_bytes()
    msg: EmailMessage = email.message_from_bytes(raw, policy=policy.default)  # type: ignore[assignment]

    # Collect headers
    headers: dict[str, str | list[str]] = {}
    for key in HEADER_KEYS:
        values = msg.get_all(key, [])
        if not values:
            headers[key] = "(not present)"
        elif len(values) == 1:
            headers[key] = str(values[0])
        else:
            headers[key] = [str(v) for v in values]

    body = _get_body_text(msg)
    subject = str(msg.get("Subject", ""))

    # Run checks
    findings: list[dict[str, str]] = []
    findings.extend(check_sender_spoofing(msg))
    urls = extract_urls(body)
    for url in urls:
        findings.extend(analyze_url(url))
    findings.extend(check_attachments(msg))
    findings.extend(check_urgency(subject, body))

    score = compute_score(findings)

    render_report(headers, findings, urls, score)

    if output:
        report = build_json_report(filepath, headers, findings, urls, score)
        Path(output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        console.print(f"[dim]JSON report written to {output}[/]")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="phish-detect",
        description="Analyze email files (.eml) for phishing indicators.",
    )
    parser.add_argument(
        "file",
        help="Path to an .eml or raw email text file to analyze",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Export analysis report to a JSON file",
    )

    args = parser.parse_args()
    analyze(args.file, args.output)


if __name__ == "__main__":
    main()
