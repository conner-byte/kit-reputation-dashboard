#!/usr/bin/env python3
"""IP + Domain Reputation Checker — DNSBL, VirusTotal, DNS health, HTML dashboard."""

import json
import socket
import datetime
import time
import threading
import urllib.request
import urllib.error
import concurrent.futures
from pathlib import Path

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    print("Warning: dnspython not installed. Run: pip3 install dnspython")

# ──────────────────────────────────────────────────────────────────────────────
# Blacklist definitions — IPs
# ──────────────────────────────────────────────────────────────────────────────

IP_DNSBLS = [
    {"name": "Spamhaus ZEN",      "zone": "zen.spamhaus.org",         "category": "Spamhaus",    "weight": 10, "removal_url": "https://check.spamhaus.org/"},
    {"name": "Spamhaus SBL",      "zone": "sbl.spamhaus.org",         "category": "Spamhaus",    "weight": 10, "removal_url": "https://www.spamhaus.org/sbl/removal/form/"},
    {"name": "Spamhaus XBL",      "zone": "xbl.spamhaus.org",         "category": "Spamhaus",    "weight": 8,  "removal_url": "https://www.abuseat.org/lookup.cgi"},
    {"name": "Spamhaus PBL",      "zone": "pbl.spamhaus.org",         "category": "Spamhaus",    "weight": 4,  "removal_url": "https://www.spamhaus.org/pbl/removal/form/"},
    {"name": "SpamCop",           "zone": "bl.spamcop.net",           "category": "SpamCop",     "weight": 8,  "removal_url": "https://www.spamcop.net/bl.shtml"},
    {"name": "Barracuda",         "zone": "b.barracuda.com",          "category": "Barracuda",   "weight": 7,  "removal_url": "https://www.barracudacentral.org/rbl/removal-request"},
    {"name": "SORBS Spam",        "zone": "spam.dnsbl.sorbs.net",     "category": "SORBS",       "weight": 7,  "removal_url": "https://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS Web",         "zone": "web.dnsbl.sorbs.net",      "category": "SORBS",       "weight": 5,  "removal_url": "https://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS Zombie",      "zone": "zombie.dnsbl.sorbs.net",   "category": "SORBS",       "weight": 8,  "removal_url": "https://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS DUL",         "zone": "dul.dnsbl.sorbs.net",      "category": "SORBS",       "weight": 3,  "removal_url": "https://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS Problems",    "zone": "problems.dnsbl.sorbs.net", "category": "SORBS",       "weight": 6,  "removal_url": "https://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS HTTP",        "zone": "http.dnsbl.sorbs.net",     "category": "SORBS",       "weight": 5,  "removal_url": "https://www.sorbs.net/lookup.shtml"},
    {"name": "SORBS SMTP",        "zone": "smtp.dnsbl.sorbs.net",     "category": "SORBS",       "weight": 6,  "removal_url": "https://www.sorbs.net/lookup.shtml"},
    {"name": "CBL (Spamhaus XBL)","zone": "cbl.abuseat.org",         "category": "CBL",         "weight": 9,  "removal_url": "https://www.abuseat.org/lookup.cgi"},
    {"name": "Abuse.ch Drone",    "zone": "drone.abuse.ch",           "category": "Abuse.ch",    "weight": 8,  "removal_url": "https://abuse.ch/"},
    {"name": "DroneBL",           "zone": "dnsbl.dronebl.org",        "category": "DroneBL",     "weight": 7,  "removal_url": "https://dronebl.org/lookup"},
    {"name": "SpamRats All",      "zone": "all.spamrats.com",         "category": "SpamRats",    "weight": 6,  "removal_url": "https://www.spamrats.com/removal.php"},
    {"name": "SpamRats Dyna",     "zone": "dyna.spamrats.com",        "category": "SpamRats",    "weight": 4,  "removal_url": "https://www.spamrats.com/removal.php"},
    {"name": "SpamRats NoPtr",    "zone": "noptr.spamrats.com",       "category": "SpamRats",    "weight": 3,  "removal_url": "https://www.spamrats.com/removal.php"},
    {"name": "MailSpike BL",      "zone": "bl.mailspike.net",         "category": "MailSpike",   "weight": 6,  "removal_url": "https://www.mailspike.net/"},
    {"name": "PSBL",              "zone": "psbl.surriel.com",         "category": "PSBL",        "weight": 5,  "removal_url": "https://psbl.surriel.com/"},
    {"name": "WPBL",              "zone": "db.wpbl.info",             "category": "WPBL",        "weight": 5,  "removal_url": "http://www.wpbl.info/"},
    {"name": "Lashback UBL",      "zone": "ubl.lashback.com",        "category": "Lashback",    "weight": 5,  "removal_url": "https://www.lashback.com/blacklist/"},
    {"name": "Manitu",            "zone": "ix.dnsbl.manitu.net",      "category": "Manitu",      "weight": 6,  "removal_url": "https://www.dnsbl.manitu.net/"},
    {"name": "GBUDB Truncate",    "zone": "truncate.gbudb.net",       "category": "GBUDB",       "weight": 6,  "removal_url": "https://www.gbudb.com/truncate/index.jsp"},
    {"name": "BlockList.de",      "zone": "bl.blocklist.de",          "category": "BlockList.de","weight": 6,  "removal_url": "https://www.blocklist.de/en/index.html"},
    {"name": "0Spam",             "zone": "bl.0spam.org",             "category": "0Spam",       "weight": 5,  "removal_url": "https://0spam.org/"},
    {"name": "S5H",               "zone": "all.s5h.net",              "category": "S5H",         "weight": 5,  "removal_url": "https://www.slashsecure.com/"},
]

# ──────────────────────────────────────────────────────────────────────────────
# Blacklist definitions — Domains
# ──────────────────────────────────────────────────────────────────────────────

DOMAIN_DNSBLS = [
    {"name": "Spamhaus DBL",        "zone": "dbl.spamhaus.org",   "category": "Spamhaus",  "weight": 10, "removal_url": "https://www.spamhaus.org/dbl/removal/form/"},
    {"name": "SURBL Multi",         "zone": "multi.surbl.org",    "category": "SURBL",     "weight": 9,  "removal_url": "https://www.surbl.org/surbl-analysis"},
    {"name": "SURBL Spam (SC)",     "zone": "sc.surbl.org",       "category": "SURBL",     "weight": 8,  "removal_url": "https://www.surbl.org/surbl-analysis"},
    {"name": "SURBL Malware (MW)",  "zone": "mw.surbl.org",       "category": "SURBL",     "weight": 9,  "removal_url": "https://www.surbl.org/surbl-analysis"},
    {"name": "SURBL Phish (PH)",    "zone": "ph.surbl.org",       "category": "SURBL",     "weight": 9,  "removal_url": "https://www.surbl.org/surbl-analysis"},
    {"name": "SURBL Credit (CR)",   "zone": "cr.surbl.org",       "category": "SURBL",     "weight": 7,  "removal_url": "https://www.surbl.org/surbl-analysis"},
    {"name": "URIBL Black",         "zone": "black.uribl.com",    "category": "URIBL",     "weight": 10, "removal_url": "https://admin.uribl.com/?section=removal"},
    {"name": "URIBL Multi",         "zone": "multi.uribl.com",    "category": "URIBL",     "weight": 8,  "removal_url": "https://admin.uribl.com/?section=removal"},
    {"name": "URIBL Grey",          "zone": "grey.uribl.com",     "category": "URIBL",     "weight": 5,  "removal_url": "https://admin.uribl.com/?section=removal"},
    {"name": "URIBL Red",           "zone": "red.uribl.com",      "category": "URIBL",     "weight": 7,  "removal_url": "https://admin.uribl.com/?section=removal"},
    {"name": "ivmURI",              "zone": "uribl.swinog.ch",    "category": "ivmURI",    "weight": 6,  "removal_url": "https://uribl.swinog.ch/"},
    {"name": "0Spam Domain",        "zone": "uri.0spam.org",      "category": "0Spam",     "weight": 5,  "removal_url": "https://0spam.org/"},
]

# ──────────────────────────────────────────────────────────────────────────────
# VirusTotal false-positive / delisting contacts (network indicators)
# ──────────────────────────────────────────────────────────────────────────────

VT_FP_CONTACTS = {
    "Abusix":                   "https://lookup.abusix.com/",
    "CRDF":                     "https://threatcenter.crdf.fr/false_positive.html",
    "Google Safebrowsing":      "https://safebrowsing.google.com/safebrowsing/report_error/?hl=en",
    "Google Safe Browsing":     "https://safebrowsing.google.com/safebrowsing/report_error/?hl=en",
    "GreenSnow":                "https://greensnow.co/contact",
    "Netcraft":                 "https://report.netcraft.com/report/mistake",
    "OpenPhish":                "https://openphish.com/faq.html",
    "PhishTank":                "https://www.phishtank.com/contact.php",
    "Scumware.org":             "https://www.scumware.org/removals.php",
    "Spam404":                  "https://www.spam404.com/revision-request-domain.html",
    "Spamhaus":                 "https://www.spamhaus.org/dbl/removal/form/",
    "Stopforumspam":            "https://www.stopforumspam.com/removal",
    "StopForumSpam":            "https://www.stopforumspam.com/removal",
    "URLhaus":                  "https://urlhaus.abuse.ch/",
    "alphaMountain.ai":         "https://alphamountain.ai/contact/",
    "Forcepoint ThreatSeeker": "https://www.forcepoint.com/support",
    "Webroot":                  "https://www.brightcloud.com/tools/change-request.php",
    "Sophos":                   "https://support.sophos.com/support/s/",
    "Fortinet":                 "https://www.fortiguard.com/faq/classificationdispute",
    "Kaspersky":                "https://opentip.kaspersky.com/",
    "BitDefender":              "https://www.bitdefender.com/consumer/support/answer/29358/",
    "Avira":                    "https://www.avira.com/en/analysis/submit",
    "ESET":                     "https://support.eset.com/en/submit-a-sample-or-false-positive-for-detection",
    "CrowdStrike Falcon":       "https://www.crowdstrike.com/resources/false-positive-reporting/",
    "Symantec":                 "https://submit.symantec.com/false_positive/",
    "Trustwave":                "https://www.trustwave.com/en-us/company/contact-us/",
    "CINS Army":                "http://cinsscore.com/#contact",
    "criminal.ip":              "https://www.criminalip.io/",
    "Dr.Web":                   "https://vms.drweb.com/sendvirus/?lng=en",
    "Emsisoft":                 "https://www.emsisoft.com/en/support/contact/",
    "G-Data":                   "https://www.gdata.de/en/about-g-data/contact",
    "Ikarus":                   "https://www.ikarussecurity.com/support/",
    "Malwarebytes":             "https://www.malwarebytes.com/lp/false-positive",
    "Palo Alto Networks":       "https://urlfiltering.paloaltonetworks.com/query.aspx",
    "TrendMicro":               "https://global.sitesafety.trendmicro.com/",
    "Trend Micro":              "https://global.sitesafety.trendmicro.com/",
    "ZeroFox":                  "https://www.zerofox.com/contact/",
    "SOCRadar":                 "https://socradar.io/contact/",
    "Yandex Safebrowsing":      "https://yandex.com/support/search/troubleshooting/ban.html",
    "Zvelo":                    "https://zvelo.com/contact/",
    # Email-only contacts (displayed as copyable text)
    "Chong Lua Dao":            "[email protected]",
    "Criminal IP":              "[email protected]",
    "CyRadar":                  "[email protected]",
    "MalwareURL":               "[email protected]",
    "Phishing Database":        "https://github.com/phishing-Database/Phishing.Database/?tab=readme-ov-file#requests--support",
    "Xcitium Verdict Cloud":    "[email protected]",
    "AlienVault":               "[email protected]",
    "AutoShun":                 "[email protected]",
    "Blueliv":                  "[email protected]",
    "Clean-MX":                 "[email protected]",
    "DNS8":                     "[email protected]",
    "Hunt.io Intelligence":     "[email protected]",
    "OpenPhish":                "[email protected]",
    "Sansec eComscan":          "[email protected]",
    "URLQuery":                 "[email protected]",
}

# ──────────────────────────────────────────────────────────────────────────────
# DNSBL response validation
# Spamhaus, SURBL, and URIBL return 127.255.x.x codes (and 127.0.0.254) when
# queries arrive via a public resolver instead of a registered direct feed.
# These are NOT real listings — treat them as errors so they don't show as hits.
# ──────────────────────────────────────────────────────────────────────────────

# Known open-resolver / administrative block codes
_DNSBL_ERROR_RESPONSES = {
    "127.255.255.252",  # Spamhaus: typing error in DNSBL name
    "127.255.255.254",  # Spamhaus/SURBL: query via public/open resolver
    "127.255.255.255",  # Spamhaus: localhost queries not supported
    "127.0.0.1",        # URIBL: query via public/open resolver (access denied)
    "127.0.0.254",      # URIBL: alternate open-resolver block code
    "127.0.0.255",      # generic DNSBL error sentinel
}


def _is_error_response(response: str) -> bool:
    """Return True if every address in the response is an administrative error code."""
    if not response:
        return False
    addrs = [a.strip() for a in response.split(",")]
    return all(
        a in _DNSBL_ERROR_RESPONSES or (a.startswith("127.255."))
        for a in addrs
    )


# ──────────────────────────────────────────────────────────────────────────────
# VirusTotal rate limiter — free tier: 4 req/min
# ──────────────────────────────────────────────────────────────────────────────

_vt_lock = threading.Lock()
_vt_last_call_time = 0.0
VT_INTERVAL = 16.0


def _vt_wait():
    global _vt_last_call_time
    with _vt_lock:
        now = time.monotonic()
        gap = VT_INTERVAL - (now - _vt_last_call_time)
        if gap > 0:
            time.sleep(gap)
        _vt_last_call_time = time.monotonic()

# ──────────────────────────────────────────────────────────────────────────────
# Data fetching — shared
# ──────────────────────────────────────────────────────────────────────────────

def fetch_virustotal(resource: str, resource_type: str, api_key: str, timeout: int) -> dict:
    """resource_type: 'ip_addresses' or 'domains'"""
    result = {
        "available": False, "error": None, "reputation": None,
        "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
        "total_engines": 0, "flagged_by": [], "community_score": None,
        "last_analysis_date": None, "categories": {},
    }
    if not api_key:
        return result
    _vt_wait()
    try:
        url = f"https://www.virustotal.com/api/v3/{resource_type}/{resource}"
        req = urllib.request.Request(url, headers={
            "x-apikey": api_key,
            "User-Agent": "ip-reputation-checker/1.0",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        attrs    = data.get("data", {}).get("attributes", {})
        stats    = attrs.get("last_analysis_stats", {})
        analysis = attrs.get("last_analysis_results", {})
        epoch    = attrs.get("last_analysis_date")
        flagged  = sorted(
            [{"engine": e, "category": i.get("category",""),
              "result": i.get("result","") or i.get("category","")}
             for e, i in analysis.items() if i.get("category") in ("malicious","suspicious")],
            key=lambda x: (x["category"] != "malicious", x["engine"].lower()),
        )
        result.update({
            "available": True,
            "reputation": attrs.get("reputation"),
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "flagged_by":  flagged,
            "community_score": attrs.get("reputation"),
            "categories": attrs.get("categories", {}),
            "last_analysis_date": (
                datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc).strftime("%Y-%m-%d")
                if epoch else None
            ),
        })
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result

# ──────────────────────────────────────────────────────────────────────────────
# Data fetching — IPs
# ──────────────────────────────────────────────────────────────────────────────

def reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def check_ip_dnsbl(ip: str, dnsbl: dict, timeout: int) -> dict:
    query = f"{reverse_ip(ip)}.{dnsbl['zone']}"
    result = {"name": dnsbl["name"], "zone": dnsbl["zone"], "category": dnsbl["category"],
              "weight": dnsbl["weight"], "listed": False, "response": None, "error": None}
    if not HAS_DNSPYTHON:
        try:
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(query)
            result["listed"] = True
        except socket.gaierror:
            pass
        except Exception as e:
            result["error"] = str(e)
        return result
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(query, "A")
        response = ", ".join(str(r) for r in answers)
        if _is_error_response(response):
            result["error"] = f"blocked/open-resolver ({response})"
        else:
            result["listed"] = True
            result["response"] = response
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.Timeout:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:60]
    return result


def fetch_ip_geo(ip: str, timeout: int) -> dict:
    info = {"org": "Unknown", "country": "Unknown", "isp": "Unknown",
            "city": "Unknown", "region": "Unknown"}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,org,isp"
        req = urllib.request.Request(url, headers={"User-Agent": "ip-reputation-checker/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                info.update({
                    "org":     data.get("org", "Unknown"),
                    "isp":     data.get("isp", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "city":    data.get("city", "Unknown"),
                    "region":  data.get("regionName", "Unknown"),
                })
    except Exception:
        pass
    return info


def check_ip_dnsbl_geo(ip: str, timeout: int) -> dict:
    with concurrent.futures.ThreadPoolExecutor(max_workers=28) as ex:
        dnsbl_futures = {ex.submit(check_ip_dnsbl, ip, bl, timeout): bl for bl in IP_DNSBLS}
        geo_future    = ex.submit(fetch_ip_geo, ip, timeout)
        dnsbl_results = [f.result() for f in concurrent.futures.as_completed(dnsbl_futures)]
        geo           = geo_future.result()
    dnsbl_results.sort(key=lambda r: r["name"])
    listed = [r for r in dnsbl_results if r["listed"]]
    errors = [r for r in dnsbl_results if r["error"] and not r["listed"]]
    clean  = [r for r in dnsbl_results if not r["listed"] and not r["error"]]
    return {
        "type": "ip", "ip": ip, "info": geo,
        "listed_count": len(listed), "clean_count": len(clean),
        "error_count":  len(errors), "total_checked": len(IP_DNSBLS),
        "listings": listed, "errors": errors, "all_results": dnsbl_results,
        "vt": {"available": False},
    }

# ──────────────────────────────────────────────────────────────────────────────
# Data fetching — Domains
# ──────────────────────────────────────────────────────────────────────────────

def check_domain_dnsbl(domain: str, dnsbl: dict, timeout: int) -> dict:
    query = f"{domain}.{dnsbl['zone']}"
    result = {"name": dnsbl["name"], "zone": dnsbl["zone"], "category": dnsbl["category"],
              "weight": dnsbl["weight"], "listed": False, "response": None, "error": None}
    if not HAS_DNSPYTHON:
        try:
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(query)
            result["listed"] = True
        except socket.gaierror:
            pass
        except Exception as e:
            result["error"] = str(e)
        return result
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(query, "A")
        response = ", ".join(str(r) for r in answers)
        if _is_error_response(response):
            result["error"] = f"blocked/open-resolver ({response})"
        else:
            result["listed"] = True
            result["response"] = response
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.Timeout:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:60]
    return result


def check_domain_dnsbl_and_dns(domain: str, timeout: int) -> dict:
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        dnsbl_futures = {ex.submit(check_domain_dnsbl, domain, bl, timeout): bl for bl in DOMAIN_DNSBLS}
        dnsbl_results = [f.result() for f in concurrent.futures.as_completed(dnsbl_futures)]
    dnsbl_results.sort(key=lambda r: r["name"])
    listed = [r for r in dnsbl_results if r["listed"]]
    errors = [r for r in dnsbl_results if r["error"] and not r["listed"]]
    clean  = [r for r in dnsbl_results if not r["listed"] and not r["error"]]
    return {
        "type": "domain", "domain": domain,
        "listed_count": len(listed), "clean_count": len(clean),
        "error_count":  len(errors), "total_checked": len(DOMAIN_DNSBLS),
        "listings": listed, "errors": errors, "all_results": dnsbl_results,
        "vt": {"available": False},
    }

# ──────────────────────────────────────────────────────────────────────────────
# Score computation
# ──────────────────────────────────────────────────────────────────────────────

def compute_score(result: dict) -> tuple[int, str]:
    listed    = result["listings"]
    vt        = result["vt"]
    dnsbl_set = IP_DNSBLS if result["type"] == "ip" else DOMAIN_DNSBLS

    max_possible = sum(bl["weight"] for bl in dnsbl_set)
    penalty      = sum(r["weight"] for r in listed)
    dnsbl_score  = max(0, round(100 - (penalty / max_possible * 100)))

    if vt["available"] and vt["total_engines"] > 0:
        vt_clean_pct = (vt["harmless"] + vt["undetected"]) / vt["total_engines"]
        score = round(dnsbl_score * 0.6 + vt_clean_pct * 100 * 0.4)
    else:
        score = dnsbl_score

    vt_flagged = vt["malicious"] + vt["suspicious"] if vt["available"] else 0
    if   len(listed) == 0 and vt_flagged == 0: status = "clean"
    elif len(listed) <= 2 and vt_flagged <= 2: status = "warning"
    else:                                       status = "danger"
    return score, status

# ──────────────────────────────────────────────────────────────────────────────
# HTML helpers — shared
# ──────────────────────────────────────────────────────────────────────────────

def score_color(score: int) -> str:
    if score >= 90: return "#22c55e"
    if score >= 70: return "#f59e0b"
    if score >= 50: return "#f97316"
    return "#ef4444"


def status_badge(status: str) -> str:
    return {
        "clean":   '<span class="badge badge-clean">Clean</span>',
        "warning": '<span class="badge badge-warning">Warning</span>',
        "danger":  '<span class="badge badge-danger">Blacklisted</span>',
    }.get(status, "")


def pool_badge(label: str) -> str:
    if not label:
        return '<span class="pool-badge pool-unlabeled">Unlabeled</span>'
    return f'<span class="pool-badge">{label}</span>'


def render_vt_panel(vt: dict) -> str:
    if not vt["available"]:
        if vt.get("error"):
            return f'<div class="vt-panel vt-error"><span class="vt-logo">VirusTotal</span> Error: {vt["error"]}</div>'
        return ""
    total = vt["total_engines"]
    mal, sus, har, und = vt["malicious"], vt["suspicious"], vt["harmless"], vt["undetected"]
    mal_pct = round(mal / total * 100) if total else 0
    sus_pct = round(sus / total * 100) if total else 0
    har_pct = round(har / total * 100) if total else 0
    und_pct = max(0, 100 - mal_pct - sus_pct - har_pct)
    rep       = vt["community_score"]
    rep_str   = f"{rep:+d}" if rep is not None else "N/A"
    rep_color = "#22c55e" if (rep or 0) >= 0 else "#ef4444"
    date_str  = f" &nbsp;·&nbsp; Last scanned {vt['last_analysis_date']}" if vt["last_analysis_date"] else ""

    cats = vt.get("categories", {})
    cat_html = ""
    if cats:
        cat_items = ", ".join(f"{v}" for v in dict.fromkeys(cats.values()))
        cat_html = f'<div class="vt-cats">Categories: <span>{cat_items}</span></div>'

    flagged_rows = ""
    if vt["flagged_by"]:
        def _vt_contact_cell(engine):
            contact = VT_FP_CONTACTS.get(engine, "")
            if not contact:
                return "<td></td>"
            if contact.startswith("http"):
                return f'<td><a class="removal-link" href="{contact}" target="_blank" rel="noopener">Report FP ↗</a></td>'
            return f'<td><span class="fp-email">{contact}</span></td>'

        rows = "".join(
            f'<tr><td class="vt-engine">{r["engine"]}</td>'
            f'<td class=\'vt-cat-{"mal" if r["category"]=="malicious" else "sus"}\'>{r["category"].title()}</td>'
            f'<td class="vt-result-label">{r["result"]}</td>'
            + _vt_contact_cell(r["engine"]) + "</tr>"
            for r in vt["flagged_by"]
        )
        flagged_rows = (
            f'<details class="vt-flagged-details"><summary>Show {len(vt["flagged_by"])} flagging engine(s)</summary>'
            f'<table class="vt-flagged-table"><thead><tr><th>Engine</th><th>Category</th><th>Detection</th><th></th></tr></thead>'
            f'<tbody>{rows}</tbody></table></details>'
        )
    return f"""
<div class="vt-panel">
  <div class="vt-header">
    <span class="vt-logo">VirusTotal</span>
    <span class="vt-meta">{total} engines{date_str}</span>
    <span class="vt-rep" style="color:{rep_color}">Community score: {rep_str}</span>
  </div>
  <div class="vt-bar-wrap">
    <div class="vt-bar">
      <div class="vt-seg vt-mal" style="width:{mal_pct}%"></div>
      <div class="vt-seg vt-sus" style="width:{sus_pct}%"></div>
      <div class="vt-seg vt-har" style="width:{har_pct}%"></div>
      <div class="vt-seg vt-und" style="width:{und_pct}%"></div>
    </div>
    <div class="vt-legend">
      <span class="leg-dot leg-mal"></span>{mal} malicious &nbsp;
      <span class="leg-dot leg-sus"></span>{sus} suspicious &nbsp;
      <span class="leg-dot leg-har"></span>{har} harmless &nbsp;
      <span class="leg-dot leg-und"></span>{und} undetected
    </div>
  </div>
  {cat_html}
  {flagged_rows}
</div>"""


def render_dnsbl_row(r: dict) -> str:
    if r["listed"]:
        resp = f'<code class="response">{r["response"]}</code>' if r["response"] else ""
        url  = r.get("removal_url", "")
        link = f' <a class="removal-link" href="{url}" target="_blank" rel="noopener">Request removal ↗</a>' if url else ""
        return (f'<tr class="listed-row"><td>🔴</td><td><strong>{r["name"]}</strong></td>'
                f'<td>{r["category"]}</td><td class="listed-text">Listed{" — "+resp if resp else ""}{link}</td></tr>')
    elif r["error"]:
        return (f'<tr class="error-row"><td>⚠️</td><td>{r["name"]}</td>'
                f'<td>{r["category"]}</td><td class="error-text">Error: {r["error"]}</td></tr>')
    return (f'<tr class="clean-row"><td>✅</td><td>{r["name"]}</td>'
            f'<td>{r["category"]}</td><td class="clean-text">Not listed</td></tr>')


def render_listing_alert(listings: list, label: str = "DNSBL") -> str:
    if not listings:
        return ""
    rows = "".join(
        f'<li><span class="bl-name">{r["name"]}</span> <span class="bl-cat">({r["category"]})</span>'
        + (f' — <code>{r["response"]}</code>' if r["response"] else "")
        + (f' <a class="removal-link" href="{r["removal_url"]}" target="_blank" rel="noopener">Request removal ↗</a>' if r.get("removal_url") else "")
        + "</li>"
        for r in sorted(listings, key=lambda x: -x["weight"])
    )
    return (f'<div class="listing-alert"><strong>⚠ Active {label} Listings ({len(listings)})</strong>'
            f'<ul>{rows}</ul></div>')


def render_pool_section(pool_name: str, pool_results: list, pool_idx: int,
                        section_type: str = "ip") -> str:
    total      = len(pool_results)
    clean      = sum(1 for r in pool_results if r["status"] == "clean")
    warn       = sum(1 for r in pool_results if r["status"] == "warning")
    danger     = sum(1 for r in pool_results if r["status"] == "danger")
    avg_score  = round(sum(r["score"] for r in pool_results) / total) if total else 0
    pool_color = score_color(avg_score)
    display    = pool_name if pool_name else "Unlabeled"
    prefix     = f"{section_type}-pool"

    if section_type == "domain":
        cards = "".join(render_domain_card(r, f"{prefix}{pool_idx}-{i}") for i, r in enumerate(pool_results))
    else:
        cards = "".join(render_ip_card(r, f"{prefix}{pool_idx}-{i}") for i, r in enumerate(pool_results))

    return f"""
<div class="pool-section" id="{prefix}-{pool_idx}">
  <div class="pool-header">
    <div class="pool-title-row">
      <h2 class="pool-name">{display}</h2>
      <div class="pool-score-chip" style="--pc:{pool_color}">Avg {avg_score}/100</div>
    </div>
    <div class="pool-stats">
      <span class="ps-total">{total} {"domains" if section_type == "domain" else "IPs"}</span>
      <span class="ps-sep">·</span>
      <span class="ps-clean">✅ {clean} clean</span>
      <span class="ps-sep">·</span>
      <span class="ps-warn">⚠ {warn} warning</span>
      <span class="ps-sep">·</span>
      <span class="ps-danger">🔴 {danger} blacklisted</span>
    </div>
  </div>
  <div class="pool-cards">{cards}</div>
</div>"""

# ──────────────────────────────────────────────────────────────────────────────
# HTML — Domain cards
# ──────────────────────────────────────────────────────────────────────────────

def render_domain_card(result: dict, card_id: str) -> str:
    domain  = result["domain"]
    score   = result["score"]
    status  = result["status"]
    label   = result.get("label", "")
    color   = score_color(score)

    vt_panel    = render_vt_panel(result["vt"])
    listing_sec = render_listing_alert(result["listings"], "Domain DNSBL")
    dnsbl_rows  = "".join(render_dnsbl_row(r) for r in result["all_results"])

    return f"""
<div class="ip-card domain-card" id="{card_id}">
  <div class="ip-card-header">
    <div class="ip-title">
      <span class="ip-address domain-name">{domain}</span>
      {status_badge(status)}
      {pool_badge(label)}
    </div>
    <div class="score-ring" style="--score-color:{color};">
      <span class="score-number">{score}</span>
      <span class="score-label">/ 100</span>
    </div>
  </div>
  <div class="ip-meta">
    <div class="meta-item"><span class="meta-key">Domain DNSBL</span><span class="meta-val">{result['listed_count']} listed &nbsp;·&nbsp; {result['clean_count']} clean &nbsp;·&nbsp; {result['total_checked']} total</span></div>
  </div>
  {listing_sec}
  {vt_panel}
  <details class="dnsbl-details">
    <summary>Show all {result['total_checked']} domain blacklist results</summary>
    <table class="dnsbl-table">
      <thead><tr><th></th><th>Blacklist</th><th>Category</th><th>Result</th></tr></thead>
      <tbody>{dnsbl_rows}</tbody>
    </table>
  </details>
</div>"""

# ──────────────────────────────────────────────────────────────────────────────
# HTML — IP cards
# ──────────────────────────────────────────────────────────────────────────────

def render_ip_card(result: dict, card_id: str) -> str:
    ip    = result["ip"]
    info  = result["info"]
    score = result["score"]
    color = score_color(score)

    vt_panel    = render_vt_panel(result["vt"])
    listing_sec = render_listing_alert(result["listings"], "DNSBL")
    dnsbl_rows  = "".join(render_dnsbl_row(r) for r in result["all_results"])
    label       = result.get("label", "")

    return f"""
<div class="ip-card" id="{card_id}">
  <div class="ip-card-header">
    <div class="ip-title">
      <span class="ip-address">{ip}</span>
      {status_badge(result["status"])}
      {pool_badge(label)}
    </div>
    <div class="score-ring" style="--score-color:{color};">
      <span class="score-number">{score}</span>
      <span class="score-label">/ 100</span>
    </div>
  </div>
  <div class="ip-meta">
    <div class="meta-item"><span class="meta-key">ISP / Org</span><span class="meta-val">{info['org']}</span></div>
    <div class="meta-item"><span class="meta-key">Location</span><span class="meta-val">{info['city']}, {info['region']}, {info['country']}</span></div>
    <div class="meta-item"><span class="meta-key">DNSBL</span><span class="meta-val">{result['listed_count']} listed &nbsp;·&nbsp; {result['clean_count']} clean &nbsp;·&nbsp; {result['total_checked']} total</span></div>
  </div>
  {listing_sec}
  {vt_panel}
  <details class="dnsbl-details">
    <summary>Show all {result['total_checked']} DNSBL results</summary>
    <table class="dnsbl-table">
      <thead><tr><th></th><th>Blacklist</th><th>Category</th><th>Result</th></tr></thead>
      <tbody>{dnsbl_rows}</tbody>
    </table>
  </details>
</div>"""

# ──────────────────────────────────────────────────────────────────────────────
# HTML — full page
# ──────────────────────────────────────────────────────────────────────────────

def generate_html(domain_groups: list, ip_groups: list, generated_at: datetime.datetime) -> str:
    all_domains = [r for _, g in domain_groups for r in g]
    all_ips     = [r for _, g in ip_groups     for r in g]
    all_results = all_domains + all_ips

    total      = len(all_results)
    clean_all  = sum(1 for r in all_results if r["status"] == "clean")
    warn_all   = sum(1 for r in all_results if r["status"] == "warning")
    danger_all = sum(1 for r in all_results if r["status"] == "danger")
    timestamp  = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    has_vt     = any(r["vt"]["available"] for r in all_results)
    sources    = f"DNSBL/SURBL/URIBL" + (" + VirusTotal" if has_vt else "") + " + ip-api.com"

    domain_sections_html = "".join(
        render_pool_section(name, group, i, "domain")
        for i, (name, group) in enumerate(domain_groups)
    )
    ip_sections_html = "".join(
        render_pool_section(name, group, i, "ip")
        for i, (name, group) in enumerate(ip_groups)
    )

    domain_nav = "".join(
        f'<a href="#domain-pool-{i}" class="nav-pool">{n or "Unlabeled"} <span class="nav-count">{len(g)}</span></a>'
        for i, (n, g) in enumerate(domain_groups)
    )
    ip_nav = "".join(
        f'<a href="#ip-pool-{i}" class="nav-pool">{n or "Unlabeled"} <span class="nav-count">{len(g)}</span></a>'
        for i, (n, g) in enumerate(ip_groups)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IP &amp; Domain Reputation Dashboard — {timestamp}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; min-height: 100vh; }}

    .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); padding: 2rem; border-bottom: 1px solid #1e293b; }}
    .header h1 {{ font-size: 1.75rem; font-weight: 700; color: #f1f5f9; }}
    .header .subtitle {{ color: #94a3b8; font-size: 0.9rem; margin-top: 0.25rem; }}

    .summary-bar {{ display: flex; gap: 1rem; padding: 1.5rem 2rem; background: #0f172a; flex-wrap: wrap; }}
    .stat-card {{ flex: 1; min-width: 130px; background: #1e293b; border-radius: 12px; padding: 1.2rem 1.5rem; border: 1px solid #334155; }}
    .stat-card .stat-val {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
    .stat-card .stat-label {{ font-size: 0.75rem; color: #94a3b8; margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .stat-total .stat-val  {{ color: #60a5fa; }}
    .stat-clean .stat-val  {{ color: #22c55e; }}
    .stat-warn .stat-val   {{ color: #f59e0b; }}
    .stat-danger .stat-val {{ color: #ef4444; }}

    /* Tabs */
    .tab-bar {{ display: flex; background: #0f172a; border-bottom: 1px solid #1e293b; padding: 0 2rem; gap: 0; }}
    .tab-btn {{ padding: 0.85rem 1.5rem; font-size: 0.9rem; font-weight: 600; color: #64748b; background: none; border: none; border-bottom: 3px solid transparent; cursor: pointer; transition: color 0.15s, border-color 0.15s; white-space: nowrap; }}
    .tab-btn:hover {{ color: #cbd5e1; }}
    .tab-btn.active {{ color: #60a5fa; border-bottom-color: #60a5fa; }}
    .tab-count {{ display: inline-block; background: #1e293b; border-radius: 999px; font-size: 0.68rem; padding: 0.1rem 0.45rem; margin-left: 0.4rem; color: #94a3b8; font-weight: 500; }}
    .tab-btn.active .tab-count {{ background: #1e3a5f; color: #93c5fd; }}

    /* Pool nav */
    .pool-nav {{ display: flex; gap: 0.5rem; padding: 0.75rem 2rem; flex-wrap: wrap; align-items: center; background: #0a1120; border-bottom: 1px solid #1e293b; }}
    .pool-nav-label {{ font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-right: 0.25rem; white-space: nowrap; }}
    .nav-pool {{ display: flex; align-items: center; gap: 0.35rem; padding: 0.25rem 0.7rem; border-radius: 999px; font-size: 0.78rem; font-weight: 600; text-decoration: none; background: #0f172a; border: 1px solid #334155; color: #cbd5e1; }}
    .nav-pool:hover {{ border-color: #60a5fa; color: #60a5fa; }}
    .nav-count {{ background: #334155; border-radius: 999px; font-size: 0.62rem; padding: 0.05rem 0.35rem; color: #94a3b8; }}

    /* Tab panels */
    .tab-panel {{ display: none; }}
    .tab-panel.active {{ display: block; }}

    .content {{ padding: 2rem; display: flex; flex-direction: column; gap: 2.5rem; max-width: 1100px; margin: 0 auto; }}

    /* Pool section */
    .pool-section {{ display: flex; flex-direction: column; gap: 1rem; }}
    .pool-header {{ background: #162032; border: 1px solid #1e3a5f; border-radius: 12px; padding: 1.25rem 1.5rem; }}
    .pool-title-row {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 0.6rem; flex-wrap: wrap; }}
    .pool-name {{ font-size: 1.2rem; font-weight: 700; color: #f1f5f9; }}
    .pool-score-chip {{ padding: 0.2rem 0.75rem; border-radius: 999px; font-size: 0.78rem; font-weight: 700; border: 1.5px solid var(--pc); color: var(--pc); background: #0f172a; }}
    .pool-stats {{ font-size: 0.8rem; color: #94a3b8; display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }}
    .ps-sep {{ color: #334155; }}
    .ps-clean  {{ color: #22c55e; }}
    .ps-warn   {{ color: #f59e0b; }}
    .ps-danger {{ color: #ef4444; }}
    .pool-cards {{ display: flex; flex-direction: column; gap: 0.875rem; }}

    /* Cards */
    .ip-card {{ background: #1e293b; border-radius: 14px; border: 1px solid #334155; overflow: hidden; }}
    .domain-card {{ border-color: #1e3a5f; }}
    .ip-card-header {{ display: flex; justify-content: space-between; align-items: center; padding: 1.1rem 1.5rem; background: #162032; border-bottom: 1px solid #334155; flex-wrap: wrap; gap: 0.75rem; }}
    .domain-card .ip-card-header {{ border-bottom-color: #1e3a5f; }}
    .ip-title {{ display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }}
    .ip-address {{ font-family: monospace; font-size: 1.2rem; font-weight: 700; color: #f1f5f9; }}
    .domain-name {{ font-size: 1.1rem; }}

    .badge {{ padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}
    .badge-clean   {{ background: #052e16; color: #22c55e; border: 1px solid #166534; }}
    .badge-warning {{ background: #1c1009; color: #f59e0b; border: 1px solid #78350f; }}
    .badge-danger  {{ background: #1a0505; color: #ef4444; border: 1px solid #7f1d1d; }}
    .pool-badge {{ padding: 0.15rem 0.6rem; border-radius: 999px; font-size: 0.7rem; font-weight: 500; background: #0f172a; border: 1px solid #334155; color: #94a3b8; }}
    .pool-unlabeled {{ color: #475569; border-color: #1e293b; }}

    .score-ring {{ text-align: center; background: #0f172a; border-radius: 10px; padding: 0.6rem 1rem; border: 2px solid var(--score-color); }}
    .score-number {{ font-size: 1.5rem; font-weight: 800; color: var(--score-color); display: block; line-height: 1; }}
    .score-label  {{ font-size: 0.65rem; color: #94a3b8; }}

    .ip-meta {{ display: flex; flex-wrap: wrap; border-bottom: 1px solid #334155; }}
    .domain-card .ip-meta {{ border-bottom-color: #1e3a5f; }}
    .meta-item {{ flex: 1; min-width: 200px; padding: 0.8rem 1.5rem; border-right: 1px solid #334155; }}
    .meta-item:last-child {{ border-right: none; }}
    .meta-key {{ display: block; font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 0.2rem; }}
    .meta-val {{ font-size: 0.85rem; color: #cbd5e1; }}

    /* Listing alert */
    .listing-alert {{ margin: 1rem 1.5rem 0; background: #1a0505; border: 1px solid #7f1d1d; border-left: 4px solid #ef4444; border-radius: 8px; padding: 0.875rem 1.25rem; }}
    .listing-alert strong {{ color: #ef4444; display: block; margin-bottom: 0.4rem; font-size: 0.85rem; }}
    .listing-alert ul {{ list-style: none; display: flex; flex-direction: column; gap: 0.25rem; }}
    .listing-alert li {{ font-size: 0.82rem; color: #fca5a5; }}
    .bl-name {{ font-weight: 600; }}
    .bl-cat  {{ color: #94a3b8; }}

    /* VirusTotal panel */
    .vt-panel {{ margin: 1rem 1.5rem 0; background: #0f1e35; border: 1px solid #1e3a5f; border-left: 4px solid #3b82f6; border-radius: 8px; padding: 0.875rem 1.25rem; }}
    .vt-panel.vt-error {{ color: #94a3b8; font-size: 0.82rem; }}
    .vt-header {{ display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.6rem; }}
    .vt-logo {{ font-weight: 700; font-size: 0.82rem; color: #60a5fa; letter-spacing: 0.02em; }}
    .vt-meta {{ font-size: 0.72rem; color: #64748b; }}
    .vt-rep  {{ font-size: 0.78rem; font-weight: 600; margin-left: auto; }}
    .vt-bar  {{ display: flex; height: 9px; border-radius: 999px; overflow: hidden; background: #1e293b; margin-bottom: 0.4rem; }}
    .vt-seg  {{ height: 100%; }}
    .vt-mal  {{ background: #ef4444; }}
    .vt-sus  {{ background: #f97316; }}
    .vt-har  {{ background: #22c55e; }}
    .vt-und  {{ background: #334155; }}
    .vt-legend {{ font-size: 0.7rem; color: #94a3b8; display: flex; flex-wrap: wrap; gap: 0 0.5rem; }}
    .vt-cats {{ font-size: 0.72rem; color: #64748b; margin-top: 0.4rem; }}
    .vt-cats span {{ color: #94a3b8; }}
    .leg-dot {{ display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 3px; vertical-align: middle; }}
    .leg-mal {{ background: #ef4444; }}
    .leg-sus {{ background: #f97316; }}
    .leg-har {{ background: #22c55e; }}
    .leg-und {{ background: #334155; }}
    .vt-flagged-details {{ margin-top: 0.6rem; }}
    .vt-flagged-details summary {{ cursor: pointer; color: #93c5fd; font-size: 0.78rem; padding: 0.2rem 0; user-select: none; }}
    .vt-flagged-details summary:hover {{ color: #bfdbfe; }}
    .vt-flagged-table {{ width: 100%; border-collapse: collapse; margin-top: 0.4rem; font-size: 0.76rem; }}
    .vt-flagged-table th {{ text-align: left; color: #64748b; font-weight: 600; font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.25rem 0.5rem; border-bottom: 1px solid #1e3a5f; }}
    .vt-flagged-table td {{ padding: 0.25rem 0.5rem; border-bottom: 1px solid #0f1e35; }}
    .vt-engine {{ color: #cbd5e1; font-weight: 500; }}
    .vt-cat-mal {{ color: #ef4444; font-weight: 600; }}
    .vt-cat-sus {{ color: #f97316; font-weight: 600; }}
    .vt-result-label {{ color: #94a3b8; font-style: italic; }}

    /* DNSBL expand */
    .dnsbl-details {{ margin: 1rem 1.5rem 1.25rem; }}
    .dnsbl-details summary {{ cursor: pointer; color: #60a5fa; font-size: 0.82rem; padding: 0.4rem 0; user-select: none; }}
    .dnsbl-details summary:hover {{ color: #93c5fd; }}
    .dnsbl-table {{ width: 100%; border-collapse: collapse; margin-top: 0.6rem; font-size: 0.79rem; }}
    .dnsbl-table th {{ text-align: left; color: #64748b; font-weight: 600; font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.35rem 0.5rem; border-bottom: 1px solid #334155; }}
    .dnsbl-table td {{ padding: 0.35rem 0.5rem; border-bottom: 1px solid #1e293b; }}
    .listed-row {{ background: #1a0505; }}
    .listed-row td {{ color: #fca5a5; }}
    .listed-text {{ color: #ef4444 !important; font-weight: 600; }}
    .clean-text {{ color: #4ade80; }}
    .error-text {{ color: #94a3b8; font-style: italic; }}
    .error-row td {{ color: #64748b; }}
    .response {{ background: #0f172a; padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.72rem; }}
    .removal-link {{ font-size: 0.7rem; color: #60a5fa; text-decoration: none; white-space: nowrap; margin-left: 0.3rem; }}
    .removal-link:hover {{ color: #93c5fd; text-decoration: underline; }}
    .fp-email {{ font-size: 0.7rem; color: #94a3b8; font-family: monospace; user-select: all; white-space: nowrap; }}

    .footer {{ text-align: center; padding: 2rem; color: #475569; font-size: 0.8rem; }}
  </style>
</head>
<body>

<div class="header">
  <h1>🛡 IP &amp; Domain Reputation Dashboard</h1>
  <div class="subtitle">Generated {timestamp} &nbsp;·&nbsp; Sources: {sources}</div>
</div>

<div class="summary-bar">
  <div class="stat-card stat-total"><div class="stat-val">{total}</div><div class="stat-label">Total Checked</div></div>
  <div class="stat-card stat-clean"><div class="stat-val">{clean_all}</div><div class="stat-label">Clean</div></div>
  <div class="stat-card stat-warn"><div class="stat-val">{warn_all}</div><div class="stat-label">Warning</div></div>
  <div class="stat-card stat-danger"><div class="stat-val">{danger_all}</div><div class="stat-label">Blacklisted</div></div>
</div>

<div class="tab-bar">
  <button class="tab-btn active" onclick="switchTab('domains', this)">
    Domains <span class="tab-count">{len(all_domains)}</span>
  </button>
  <button class="tab-btn" onclick="switchTab('ips', this)">
    IP Pools <span class="tab-count">{len(all_ips)}</span>
  </button>
</div>

<div id="tab-domains" class="tab-panel active">
  <div class="pool-nav">
    <span class="pool-nav-label">Jump to:</span>
    {domain_nav}
  </div>
  <div class="content">
    {domain_sections_html}
  </div>
</div>

<div id="tab-ips" class="tab-panel">
  <div class="pool-nav">
    <span class="pool-nav-label">Jump to:</span>
    {ip_nav}
  </div>
  <div class="content">
    {ip_sections_html}
  </div>
</div>

<script>
  function switchTab(name, btn) {{
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    btn.classList.add('active');
    window.scrollTo({{top: 0, behavior: 'smooth'}});
  }}
</script>

<div class="footer">
  IP &amp; Domain Reputation Checker &nbsp;·&nbsp; {sources}
</div>
</body>
</html>"""

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def parse_ip_entries(raw: list) -> list[dict]:
    entries = []
    for item in raw:
        if isinstance(item, str):
            entries.append({"ip": item.strip(), "label": ""})
        else:
            label = (item.get("label") or "").strip().lstrip("-").strip()
            entries.append({"ip": item["ip"].strip(), "label": label})
    return entries


def parse_domain_entries(raw: list) -> list[dict]:
    entries = []
    for item in raw:
        if isinstance(item, str):
            entries.append({"domain": item.strip().lower(), "label": ""})
        else:
            label = (item.get("label") or "").strip().lstrip("-").strip()
            entries.append({"domain": item["domain"].strip().lower(), "label": label})
    return entries


def group_by_label(entries: list[dict]) -> list[tuple[str, list]]:
    seen: dict[str, list] = {}
    for r in entries:
        seen.setdefault(r.get("label", ""), []).append(r)
    return list(seen.items())


def publish_to_github(repo_dir: Path, latest_path: Path, now: datetime.datetime):
    import subprocess

    index_path = repo_dir / "index.html"
    index_path.write_text(latest_path.read_text(encoding="utf-8"), encoding="utf-8")

    def git(args: list[str]) -> tuple[int, str]:
        r = subprocess.run(["git", "-C", str(repo_dir)] + args,
                           capture_output=True, text=True)
        return r.returncode, (r.stdout + r.stderr).strip()

    git(["add", "index.html"])
    code, out = git(["commit", "-m", f"dashboard update {now.strftime('%Y-%m-%d %H:%M UTC')}"])
    if "nothing to commit" in out:
        print("  GitHub Pages: no changes to publish")
        return
    if code != 0:
        print(f"  GitHub Pages: commit failed — {out}")
        return

    code, out = git(["push", "origin", "main"])
    if code == 0:
        print("  GitHub Pages: published → https://conner-byte.github.io/kit-reputation-dashboard/")
    else:
        print(f"  GitHub Pages: push failed — {out}")


def main():
    import sys
    args           = set(sys.argv[1:])
    domains_only   = "--domains-only" in args
    ips_only       = "--ips-only"     in args

    script_dir = Path(__file__).parent
    with open(script_dir / "config.json") as f:
        config = json.load(f)

    ip_entries     = [] if domains_only else parse_ip_entries(config.get("ips", []))
    domain_entries = [] if ips_only     else parse_domain_entries(config.get("domains", []))
    timeout        = config.get("timeout_seconds", 10)
    vt_key         = config.get("virustotal_api_key", "")
    dqs_key        = config.get("spamhaus_dqs_key", "")
    report_dir     = script_dir / config.get("report_dir", "reports")
    report_dir.mkdir(exist_ok=True)

    if dqs_key:
        for bl in IP_DNSBLS:
            if bl["category"] == "Spamhaus":
                bl["zone"] = bl["zone"].replace(".spamhaus.org", f".{dqs_key}.dq.spamhaus.net")
        for bl in DOMAIN_DNSBLS:
            if bl["category"] == "Spamhaus":
                bl["zone"] = bl["zone"].replace(".spamhaus.org", f".{dqs_key}.dq.spamhaus.net")
        print("  Spamhaus DQS: authenticated queries enabled")

    unique_ips     = list(dict.fromkeys(e["ip"]     for e in ip_entries))
    unique_domains = list(dict.fromkeys(e["domain"] for e in domain_entries))
    total_vt       = len(unique_ips) + len(unique_domains)

    now_str  = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    dnsbl_src = f"{len(IP_DNSBLS)} IP DNSBLs + {len(DOMAIN_DNSBLS)} domain DNSBLs"
    print(f"IP & Domain Reputation Checker — {now_str}")
    print(f"  {len(unique_ips)} unique IPs  |  {len(unique_domains)} domains  |  {dnsbl_src}")
    if vt_key:
        est = round(total_vt * VT_INTERVAL / 60, 1)
        print(f"  VirusTotal: {total_vt} resources → ~{est} min (rate-limited)\n")

    # ── Phase 1: DNSBL + geo/DNS — all resources in parallel ──────────────────
    print("Phase 1: DNSBL + DNS checks (parallel)...")
    ip_data:     dict[str, dict] = {}
    domain_data: dict[str, dict] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(unique_ips) + len(unique_domains), 15)) as ex:
        ip_futures  = {ex.submit(check_ip_dnsbl_geo,          ip,  timeout): ("ip",  ip)  for ip  in unique_ips}
        dom_futures = {ex.submit(check_domain_dnsbl_and_dns, dom,  timeout): ("dom", dom) for dom in unique_domains}
        for future in concurrent.futures.as_completed({**ip_futures, **dom_futures}):
            kind, key = ({**ip_futures, **dom_futures}[future])
            result    = future.result()
            if kind == "ip":
                ip_data[key] = result
                print(f"  IP  {key}: {result['listed_count']} DNSBL listings", flush=True)
            else:
                domain_data[key] = result
                print(f"  DOM {key}: {result['listed_count']} listings", flush=True)

    # ── Phase 2: VirusTotal — sequential, rate-limited ────────────────────────
    if vt_key:
        total_vt_checks = len(unique_ips) + len(unique_domains)
        print(f"\nPhase 2: VirusTotal ({total_vt_checks} checks, ~{VT_INTERVAL}s apart)...")
        idx = 1
        for domain in unique_domains:
            print(f"  [{idx}/{total_vt_checks}] {domain} VT...", end=" ", flush=True)
            vt = fetch_virustotal(domain, "domains", vt_key, timeout)
            domain_data[domain]["vt"] = vt
            print(f"{vt['malicious']}M/{vt['suspicious']}S" if vt["available"] else f"error: {vt['error']}", flush=True)
            idx += 1
        for ip in unique_ips:
            print(f"  [{idx}/{total_vt_checks}] {ip} VT...", end=" ", flush=True)
            vt = fetch_virustotal(ip, "ip_addresses", vt_key, timeout)
            ip_data[ip]["vt"] = vt
            print(f"{vt['malicious']}M/{vt['suspicious']}S" if vt["available"] else f"error: {vt['error']}", flush=True)
            idx += 1

    # ── Score + assemble ───────────────────────────────────────────────────────
    for r in {**ip_data, **domain_data}.values():
        r["score"], r["status"] = compute_score(r)

    final_domains = []
    for entry in domain_entries:
        result = dict(domain_data[entry["domain"]])
        result["label"] = entry["label"]
        final_domains.append(result)

    final_ips = []
    for entry in ip_entries:
        result = dict(ip_data[entry["ip"]])
        result["label"] = entry["label"]
        final_ips.append(result)

    domain_groups = group_by_label(final_domains)
    ip_groups     = group_by_label(final_ips)

    # ── Generate report ────────────────────────────────────────────────────────
    now         = datetime.datetime.now(datetime.timezone.utc)
    html        = generate_html(domain_groups, ip_groups, now)
    latest_path = report_dir / "latest.html"
    dated_path  = report_dir / f"report_{now.strftime('%Y%m%d_%H%M%S')}.html"
    latest_path.write_text(html, encoding="utf-8")
    dated_path.write_text(html, encoding="utf-8")

    print(f"\nReport saved:")
    print(f"  Latest : {latest_path}")
    print(f"  Archive: {dated_path}")

    # ── Publish to GitHub Pages ────────────────────────────────────────────────
    publish_to_github(script_dir, latest_path, now)

    # ── Terminal summary ───────────────────────────────────────────────────────
    print("\n" + "═" * 72)
    print("  DOMAINS")
    print("═" * 72)
    for pool_name, pool_results in domain_groups:
        display = pool_name or "Unlabeled"
        avg = round(sum(r["score"] for r in pool_results) / len(pool_results))
        print(f"\n  Pool: {display:<25} avg {avg}/100")
        print("  " + "─" * 66)
        for r in pool_results:
            vt = r["vt"]
            vt_str = f"VT {vt['malicious']}M/{vt['suspicious']}S" if vt["available"] else "VT N/A"
            s = {"clean": "✅", "warning": "⚠ ", "danger": "🔴"}.get(r["status"], "  ")
            print(f"  {s} {r['domain']:<30} {r['score']:>4}/100  BL {r['listed_count']}/{r['total_checked']}  {vt_str}")

    print("\n" + "═" * 72)
    print("  IP POOLS")
    print("═" * 72)
    for pool_name, pool_results in ip_groups:
        display = pool_name or "Unlabeled"
        avg = round(sum(r["score"] for r in pool_results) / len(pool_results))
        c = sum(1 for r in pool_results if r["status"] == "clean")
        w = sum(1 for r in pool_results if r["status"] == "warning")
        d = sum(1 for r in pool_results if r["status"] == "danger")
        print(f"\n  Pool: {display:<25} avg {avg}/100  ✅{c} ⚠{w} 🔴{d}")
        print("  " + "─" * 66)
        for r in pool_results:
            vt  = r["vt"]
            vt_str = f"VT {vt['malicious']}M/{vt['suspicious']}S" if vt["available"] else "VT N/A"
            s = {"clean": "✅", "warning": "⚠ ", "danger": "🔴"}.get(r["status"], "  ")
            print(f"  {s} {r['ip']:<18} {r['score']:>5}/100  DNSBL {r['listed_count']}/{r['total_checked']}  {vt_str}")
    print("\n" + "═" * 72)


if __name__ == "__main__":
    main()
