"""
analyze_email.py — phishing email analyzer

Usage:
    python analyze_email.py <path/to/email.eml>        -> formatted verdict
    python analyze_email.py --json <path/to/email.eml> -> raw JSON (used by slash command)

All errors are captured and never raised.
"""

import sys
import os
import re
import io
import json
import email
import email.parser
import email.policy
import contextlib
from urllib.parse import urlparse
from datetime import datetime, timezone


# ── optional deps — degrade gracefully if missing ────────────────────────────

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


TIMEOUT = 5
URL_PATTERN = re.compile(r'https?://[^\s<>"\')\],;]+', re.IGNORECASE)

URGENCY_PATTERNS = re.compile(
    r'\b(urgent|immediately|verify within|account suspended|will be (closed|deleted|terminated)|'
    r'action required|expires in \d+|locked out|unauthorized access|unusual activity|'
    r'click here to verify|\d+ hours?|confirm now|act now|limited time)\b',
    re.IGNORECASE
)

CREDENTIAL_PATTERNS = re.compile(
    r'\b(log in|login|sign in|verify your (identity|account|password|details|information)|'
    r'enter your (password|pin|card|credit|bank|account)|'
    r'confirm your (identity|account|password|details|payment)|'
    r'update your (payment|billing|information|details))\b',
    re.IGNORECASE
)

GENERIC_GREETING = re.compile(
    r'^\s*(dear (customer|user|member|account holder|valued customer|client|sir|madam|friend)|'
    r'hello (customer|user|member)|greetings|attention (customer|user|member))',
    re.IGNORECASE | re.MULTILINE
)

KNOWN_BRANDS = {
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.ca'],
    'paypal': ['paypal.com', 'paypal.me'],
    'google': ['google.com', 'google.co.in', 'accounts.google.com', 'gmail.com'],
    'microsoft': ['microsoft.com', 'office.com', 'outlook.com', 'live.com', 'hotmail.com'],
    'apple': ['apple.com', 'icloud.com'],
    'facebook': ['facebook.com', 'fb.com', 'meta.com'],
    'netflix': ['netflix.com'],
    'instagram': ['instagram.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com'],
    'dropbox': ['dropbox.com'],
    'docusign': ['docusign.com', 'docusign.net'],
    'bank of america': ['bankofamerica.com'],
    'chase': ['chase.com', 'jpmorgan.com'],
    'wells fargo': ['wellsfargo.com'],
    'citibank': ['citibank.com', 'citi.com'],
    'dhl': ['dhl.com'],
    'fedex': ['fedex.com'],
    'ups': ['ups.com'],
    'usps': ['usps.com'],
    'irs': ['irs.gov'],
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
    'tiny.cc', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
    'rb.gy', 'v.gd', 'snip.ly', 'bl.ink',
}


# ── helpers ───────────────────────────────────────────────────────────────────

def extract_domain(address: str) -> str:
    if not address:
        return ""
    address = address.strip().lower()
    if "@" in address and "://" not in address:
        return address.split("@")[-1].strip(">").strip()
    try:
        parsed = urlparse(address)
        return parsed.netloc.split(":")[0]
    except Exception:
        return ""


def parse_email_message(raw: str) -> email.message.Message:
    parser = email.parser.Parser(policy=email.policy.default)
    return parser.parsestr(raw)


def get_body_parts(msg: email.message.Message) -> tuple[str, str]:
    plain, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain" and not plain:
                try:
                    plain = part.get_content()
                except Exception:
                    plain = part.get_payload(decode=True).decode("utf-8", errors="replace")
            elif ct == "text/html" and not html:
                try:
                    html = part.get_content()
                except Exception:
                    html = part.get_payload(decode=True).decode("utf-8", errors="replace")
    else:
        ct = msg.get_content_type()
        try:
            payload = msg.get_content()
        except Exception:
            raw_bytes = msg.get_payload(decode=True)
            payload = raw_bytes.decode("utf-8", errors="replace") if raw_bytes else ""
        if ct == "text/html":
            html = payload
        else:
            plain = payload
    return plain, html


def extract_urls(plain: str, html: str) -> list[str]:
    urls = set(URL_PATTERN.findall(plain))
    if html:
        if HAS_BS4:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(href=True):
                href = tag["href"]
                if href.startswith("http"):
                    urls.add(href)
            for tag in soup.find_all(src=True):
                src = tag["src"]
                if src.startswith("http"):
                    urls.add(src)
        else:
            urls.update(URL_PATTERN.findall(html))
    cleaned = []
    for u in urls:
        u = u.rstrip(".,;:!?)")
        if u not in cleaned:
            cleaned.append(u)
    return cleaned


def check_spf(domain: str, errors: list) -> str:
    if not HAS_DNS or not domain:
        return "UNAVAILABLE"
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=TIMEOUT)
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if txt.lower().startswith("v=spf1"):
                return "RECORD_EXISTS"
        return "NO_SPF_RECORD"
    except dns.resolver.NXDOMAIN:
        return "DOMAIN_NOT_FOUND"
    except dns.resolver.NoAnswer:
        return "NO_SPF_RECORD"
    except Exception as e:
        errors.append(f"SPF lookup failed for {domain}: {e}")
        return "UNAVAILABLE"


def check_dkim(domain: str, errors: list) -> str:
    if not HAS_DNS or not domain:
        return "UNAVAILABLE"
    selectors = ["default", "google", "mail", "dkim", "s1", "s2"]
    for selector in selectors:
        try:
            host = f"{selector}._domainkey.{domain}"
            dns.resolver.resolve(host, "TXT", lifetime=TIMEOUT)
            return "SIGNED"
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception as e:
            errors.append(f"DKIM lookup failed ({selector}._domainkey.{domain}): {e}")
            continue
    return "NOT_SIGNED"


def check_dmarc(domain: str, errors: list) -> str:
    if not HAS_DNS or not domain:
        return "UNAVAILABLE"
    try:
        host = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(host, "TXT", lifetime=TIMEOUT)
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if "v=DMARC1" in txt:
                if "p=reject" in txt or "p=quarantine" in txt:
                    return "ENFORCED"
                return "EXISTS_PERMISSIVE"
        return "MISSING"
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "MISSING"
    except Exception as e:
        errors.append(f"DMARC lookup failed for {domain}: {e}")
        return "UNAVAILABLE"


def domain_age_days(domain: str, errors: list) -> int | None:
    if not HAS_WHOIS or not domain:
        return None
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return None
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - creation).days
        return max(age, 0)
    except Exception as e:
        short = str(e).splitlines()[0][:120]
        errors.append(f"WHOIS failed for {domain}: {short}")
        return None


def follow_redirects(url: str, errors: list) -> dict:
    result = {"original": url, "final_destination": url, "final_domain": extract_domain(url)}
    if not HAS_REQUESTS:
        return result
    try:
        resp = requests.head(
            url,
            allow_redirects=True,
            timeout=TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        final_url = resp.url
        result["final_destination"] = final_url
        result["final_domain"] = extract_domain(final_url)
        result["status_code"] = resp.status_code
    except Exception as e:
        errors.append(f"URL redirect check failed for {url}: {e}")
    return result


# ── scoring ───────────────────────────────────────────────────────────────────

def score_result(result: dict, body: str) -> tuple[int, list[str]]:
    domain_checks = result.get("domain_checks", {})
    headers = result.get("headers", {})
    urls = result.get("urls", [])

    from_header = headers.get("from", "")
    from_domain = domain_checks.get("from_domain", "")
    reply_to_domain = domain_checks.get("reply_to_domain", "")
    domain_mismatch = domain_checks.get("domain_mismatch", False)
    age_days = domain_checks.get("from_domain_age_days")
    spf = domain_checks.get("spf", "UNAVAILABLE")
    dkim = domain_checks.get("dkim", "UNAVAILABLE")
    dmarc = domain_checks.get("dmarc", "UNAVAILABLE")

    score = 0
    red_flags = []

    # SPF
    if spf in ("NO_SPF_RECORD", "DOMAIN_NOT_FOUND"):
        score += 25
        red_flags.append(f"SPF record missing or domain not found for {from_domain}")

    # Domain age
    if age_days is not None and age_days < 30:
        score += 20
        red_flags.append(f"Sender domain '{from_domain}' registered only {age_days} day(s) ago")

    # Reply-To mismatch
    if domain_mismatch:
        score += 20
        red_flags.append(
            f"Reply-To domain '{reply_to_domain}' differs from sender domain '{from_domain}'"
        )

    # Brand impersonation
    display_name = ""
    if "<" in from_header:
        display_name = from_header.split("<")[0].strip().strip('"').lower()
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in display_name and not any(ld in from_domain for ld in legit_domains):
            score += 15
            red_flags.append(
                f"Brand impersonation: display name claims '{display_name.title()}' "
                f"but sending domain is '{from_domain}'"
            )
            break

    # DKIM
    if dkim == "NOT_SIGNED":
        score += 10

    # DMARC
    if dmarc == "MISSING":
        score += 10
        red_flags.append(f"No DMARC policy found for {from_domain}")

    # Urgency language
    if body:
        m = URGENCY_PATTERNS.search(body)
        if m:
            score += 10
            red_flags.append(f'Urgency/threat language: "{m.group(0)}"')

    # Credential request
    if body and CREDENTIAL_PATTERNS.search(body):
        score += 10
        red_flags.append("Email requests credentials, login, or identity verification")

    # Generic greeting
    if body and GENERIC_GREETING.search(body):
        score += 5
        red_flags.append("Generic greeting used (no recipient name)")

    # URL shorteners / unexpected redirects
    for url_info in urls:
        orig_domain = extract_domain(url_info.get("original", ""))
        final_domain = url_info.get("final_domain", "")
        if orig_domain in URL_SHORTENERS:
            score += 15
            red_flags.append(
                f"Shortened URL hides destination: {url_info['original']} "
                f"-> {url_info.get('final_destination', '?')}"
            )
            break
        if (final_domain and orig_domain and final_domain != orig_domain
                and not final_domain.endswith("." + orig_domain)
                and not orig_domain.endswith("." + final_domain)):
            score += 15
            red_flags.append(
                f"URL redirects to unexpected domain: "
                f"{url_info['original'][:60]} -> {final_domain}"
            )
            break

    # Clean signal deduction — all four must pass
    if (spf == "RECORD_EXISTS"
            and dkim == "SIGNED"
            and dmarc in ("ENFORCED", "EXISTS_PERMISSIVE")
            and age_days is not None and age_days > 365):
        score -= 30

    return min(max(score, 0), 99), red_flags


# ── formatted output ──────────────────────────────────────────────────────────

def format_verdict(result: dict, body: str) -> str:
    domain_checks = result.get("domain_checks", {})
    urls = result.get("urls", [])

    from_domain = domain_checks.get("from_domain", "unknown")
    age_days = domain_checks.get("from_domain_age_days")
    spf = domain_checks.get("spf", "UNAVAILABLE")
    dkim = domain_checks.get("dkim", "UNAVAILABLE")
    dmarc = domain_checks.get("dmarc", "UNAVAILABLE")

    score, red_flags = score_result(result, body)

    if score >= 60:
        verdict = "LIKELY PHISHING"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY LEGITIMATE"

    lines = ["", f"🚨 VERDICT: {verdict} (Confidence: {score}%)", ""]

    lines.append("📍 Red Flags Found:")
    if red_flags:
        for flag in red_flags:
            lines.append(f"  • {flag}")
    else:
        lines.append("  • None detected")

    lines += ["", "🔍 Technical Checks:"]
    lines.append(f"  • SPF:   {spf}")
    lines.append(f"  • DKIM:  {dkim}")
    lines.append(f"  • DMARC: {dmarc}")

    if age_days is not None:
        years, rem = divmod(age_days, 365)
        age_str = f"{years}yr {rem}d" if years > 0 else f"{age_days} days"
        lines.append(f"  • Sender domain age: {age_str} ({from_domain})")
    else:
        lines.append(f"  • Sender domain age: unknown ({from_domain})")

    redirects = [
        (u["original"], u.get("final_destination", ""))
        for u in urls
        if u.get("original") != u.get("final_destination")
    ]
    if redirects:
        lines.append(f"  • URL redirects: {len(redirects)} found")
        for orig, final in redirects[:3]:
            o = (orig[:60] + "...") if len(orig) > 63 else orig
            f_ = (final[:60] + "...") if len(final) > 63 else final
            lines.append(f"      {o}")
            lines.append(f"    → {f_}")
    else:
        lines.append("  • URL redirects: None detected")

    lines += ["", "💡 What to do:"]
    if verdict in ("LIKELY PHISHING", "SUSPICIOUS"):
        lines.append("  • Do NOT click any links or download attachments")
        lines.append("  • Do NOT reply or provide any personal information")
        lines.append("  • Report to IT/security team or forward to reportphishing@apwg.org")
        lines.append("  • Delete the email after reporting")
    else:
        lines.append("  • This email appears legitimate")
        lines.append("  • Always verify unexpected requests through official channels")
        lines.append("  • If you weren't expecting this, contact the sender via a known number or address")

    lines.append("")
    return "\n".join(lines)


# ── main ──────────────────────────────────────────────────────────────────────

def analyze(input_arg: str) -> dict:
    errors = []
    result = {
        "input_type": "",
        "headers": {},
        "domain_checks": {},
        "urls": [],
        "errors": errors,
    }

    raw_text = ""
    if os.path.isfile(input_arg):
        result["input_type"] = "eml"
        try:
            with open(input_arg, "rb") as f:
                raw_bytes = f.read()
            raw_text = raw_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            errors.append(f"Could not read file: {e}")
            return result
    else:
        result["input_type"] = "raw_text"
        raw_text = input_arg

    msg = parse_email_message(raw_text)

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject = msg.get("Subject", "")
    received = msg.get_all("Received") or []

    from_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to) if reply_to else ""
    return_path_domain = extract_domain(return_path) if return_path else ""

    result["headers"] = {
        "from": from_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "received_hops": len(received),
    }

    domain_mismatch = bool(reply_to_domain and from_domain and reply_to_domain != from_domain)

    spf = check_spf(from_domain, errors)
    dkim = check_dkim(from_domain, errors)
    dmarc = check_dmarc(from_domain, errors)
    age = domain_age_days(from_domain, errors)

    result["domain_checks"] = {
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "domain_mismatch": domain_mismatch,
        "from_domain_age_days": age,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
    }

    plain, html = get_body_parts(msg)
    raw_urls = extract_urls(plain, html)

    url_results = []
    for url in raw_urls[:10]:
        url_info = follow_redirects(url, errors)
        final_domain = url_info.get("final_domain", "")
        if final_domain and final_domain != from_domain:
            url_info["final_domain_age_days"] = domain_age_days(final_domain, errors)
        url_results.append(url_info)

    result["urls"] = url_results
    result["_body"] = plain or html
    return result


def main():
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf-8-sig"):
        sys.stdout.reconfigure(encoding="utf-8")

    args = sys.argv[1:]
    if not args:
        print("Usage: analyze_email.py [--json] <file.eml or raw email text>")
        sys.exit(1)

    json_mode = "--json" in args
    input_args = [a for a in args if a != "--json"]
    if not input_args:
        print("Usage: analyze_email.py [--json] <file.eml or raw email text>")
        sys.exit(1)

    output = analyze(input_args[0])
    body = output.pop("_body", "")

    if json_mode:
        print(json.dumps(output, indent=2, default=str))
    else:
        print(format_verdict(output, body))


if __name__ == "__main__":
    main()
