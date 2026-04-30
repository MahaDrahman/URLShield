import re
from urllib.parse import urlparse

# --- All detection rules in one place ---

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.xyz', '.top', '.click', '.link', '.pw'
]

BRANDS = [
    'paypal', 'amazon', 'google', 'facebook',
    'apple', 'microsoft', 'netflix', 'bank',
    'instagram', 'twitter', 'whatsapp'
]

SUSPICIOUS_WORDS = [
    'verify', 'suspended', 'confirm', 'urgent',
    'update', 'secure', 'alert', 'limited', 'winner'
]


def parse(url):
    """Break URL into parts for analysis."""
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    host   = parsed.netloc.lower()
    path   = parsed.path.lower()
    query  = parsed.query.lower()
    return url, host, path, query


def check_https(url):
    if not url.startswith("https"):
        return False, "No HTTPS — connection is not encrypted"
    return True, "HTTPS is present"


def check_tld(host):
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return False, f"Suspicious TLD '{tld}' — hackers use these for free"
    return True, "TLD looks normal"


def check_ip(host):
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        return False, "Raw IP address used instead of a domain name"
    return True, "Uses a proper domain name"


def check_subdomains(host):
    count = host.count('.')
    if count >= 3:
        return False, f"Too many subdomains ({count} dots) — real domain may be buried"
    return True, "Subdomain count is normal"


def check_brand_spoof(host):
    main = host.split('.')[-2] if '.' in host else host
    for brand in BRANDS:
        if brand in host and brand not in main:
            return False, f"Brand spoofing — '{brand}' used in subdomain, not the real domain"
    return True, "No brand name misuse detected"


def check_keywords(host, path, query):
    full = host + path + query
    for word in SUSPICIOUS_WORDS:
        if word in full:
            return False, f"Suspicious keyword '{word}' found — creates false urgency"
    return True, "No suspicious keywords found"


def check_url_length(url):
    if len(url) > 100:
        return False, f"URL is very long ({len(url)} chars) — may be hiding the real destination"
    return True, "URL length is normal"


def analyze(url):
    """
    Run all checks on a URL.
    Returns a dict with verdict, score, and detailed results.
    """
    url, host, path, query = parse(url)

    results = [
        check_https(url),
        check_tld(host),
        check_ip(host),
        check_subdomains(host),
        check_brand_spoof(host),
        check_keywords(host, path, query),
        check_url_length(url),
    ]

    check_names = [
        "HTTPS",
        "TLD",
        "IP Address",
        "Subdomains",
        "Brand Spoof",
        "Keywords",
        "URL Length",
    ]

    flags  = [(name, msg) for (name, (passed, msg)) in zip(check_names, results) if not passed]
    passes = [(name, msg) for (name, (passed, msg)) in zip(check_names, results) if passed]
    score  = len(flags)

    if score == 0:
        verdict = "SAFE"
    elif score <= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "PHISHING"

    return {
        "url":     url,
        "verdict": verdict,
        "score":   score,
        "flags":   flags,
        "passes":  passes,
    }