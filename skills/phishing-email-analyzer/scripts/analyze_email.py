"""
analyze_email.py — technical email analysis helper for the phishing-email-analyzer skill.

Usage:
    python analyze_email.py <path/to/email.eml>
    python analyze_email.py "<raw email text>"

Outputs JSON to stdout. All errors are captured in the "errors" list — never raises.
"""

import sys
import os
import re
import json
import email
import email.parser
import email.policy
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


TIMEOUT = 5  # seconds for all network calls
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\')\],;]+',
    re.IGNORECASE
)


# ── helpers ───────────────────────────────────────────────────────────────────

def extract_domain(address: str) -> str:
    """Pull the domain out of an email address or URL."""
    if not address:
        return ""
    address = address.strip().lower()
    # email address
    if "@" in address and "://" not in address:
        return address.split("@")[-1].strip(">").strip()
    # URL
    try:
        parsed = urlparse(address)
        return parsed.netloc.split(":")[0]
    except Exception:
        return ""


def parse_email_message(raw: str) -> email.message.Message:
    parser = email.parser.Parser(policy=email.policy.default)
    return parser.parsestr(raw)


def get_body_parts(msg: email.message.Message) -> tuple[str, str]:
    """Return (plain_text, html_text) from a possibly multipart message."""
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
    # deduplicate and clean trailing punctuation
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
                if "~all" in txt or "-all" in txt:
                    # record exists; actual pass/fail requires SMTP context
                    return "RECORD_EXISTS"
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
    """Check the most common DKIM selector (default._domainkey)."""
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

    # ── load the email ─────────────────────────────────────────────────────
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

    # ── extract headers ────────────────────────────────────────────────────
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

    # ── domain mismatch ────────────────────────────────────────────────────
    domain_mismatch = bool(
        reply_to_domain and from_domain and reply_to_domain != from_domain
    )

    # ── DNS checks on sender domain ────────────────────────────────────────
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

    # ── URL analysis ───────────────────────────────────────────────────────
    plain, html = get_body_parts(msg)
    raw_urls = extract_urls(plain, html)

    url_results = []
    for url in raw_urls[:10]:  # cap at 10 to stay within timeout budget
        url_info = follow_redirects(url, errors)
        # check age of the final domain too
        final_domain = url_info.get("final_domain", "")
        if final_domain and final_domain != from_domain:
            url_info["final_domain_age_days"] = domain_age_days(final_domain, errors)
        url_results.append(url_info)

    result["urls"] = url_results
    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: analyze_email.py <file.eml or raw email text>"}))
        sys.exit(1)

    input_arg = sys.argv[1]
    output = analyze(input_arg)
    print(json.dumps(output, indent=2, default=str))


if __name__ == "__main__":
    main()
