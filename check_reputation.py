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
# Slack alerts
# ──────────────────────────────────────────────────────────────────────────────

def send_slack_alert(webhook_url: str, message: str):
    if not webhook_url:
        return
    try:
        payload = json.dumps({"text": message}).encode()
        req = urllib.request.Request(
            webhook_url, data=payload,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass  # never crash the main process on a Slack failure

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


def fetch_abuseipdb(ip: str, api_key: str, timeout: int) -> dict:
    result = {"available": False, "error": None, "score": None,
              "total_reports": 0, "last_reported": None, "usage_type": None,
              "is_whitelisted": False}
    if not api_key:
        return result
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": api_key, "Accept": "application/json",
            "User-Agent": "ip-reputation-checker/1.0",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode()).get("data", {})
        result.update({
            "available":      True,
            "score":          data.get("abuseConfidenceScore", 0),
            "total_reports":  data.get("totalReports", 0),
            "last_reported":  (data.get("lastReportedAt") or "")[:10] or None,
            "usage_type":     data.get("usageType"),
            "is_whitelisted": data.get("isWhitelisted", False),
        })
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result


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
        "vt": {"available": False}, "abuseipdb": {"available": False},
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

def save_snapshot(snapshot_dir: Path, now: datetime.datetime,
                  ip_data: dict, domain_data: dict,
                  ip_entries: list, domain_entries: list) -> Path:
    snapshot_dir.mkdir(exist_ok=True)
    ips_out = {}
    for e in ip_entries:
        ip = e["ip"]
        if ip not in ip_data:
            continue
        d = ip_data[ip]
        abip = d.get("abuseipdb", {})
        vt   = d.get("vt", {})
        ips_out[ip] = {
            "label":    e["label"],
            "score":    d["score"],
            "status":   d["status"],
            "n_listed": d["listed_count"],
            "listings": [r["name"] for r in d["listings"]],
            "vt_mal":   vt["malicious"]  if vt.get("available") else None,
            "vt_sus":   vt["suspicious"] if vt.get("available") else None,
            "abip":     abip.get("score"),
        }
    domains_out = {}
    for e in domain_entries:
        dom = e["domain"]
        if dom not in domain_data:
            continue
        d  = domain_data[dom]
        vt = d.get("vt", {})
        domains_out[dom] = {
            "label":    e["label"],
            "score":    d["score"],
            "status":   d["status"],
            "n_listed": d["listed_count"],
            "listings": [r["name"] for r in d["listings"]],
            "vt_mal":   vt["malicious"]  if vt.get("available") else None,
            "vt_sus":   vt["suspicious"] if vt.get("available") else None,
        }
    snap = {"date": now.strftime("%Y-%m-%d"), "ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ips": ips_out, "domains": domains_out}
    path = snapshot_dir / f"{now.strftime('%Y-%m-%d')}.json"
    path.write_text(json.dumps(snap, separators=(",", ":")), encoding="utf-8")
    return path


def load_snapshots(snapshot_dir: Path, max_days: int = 90) -> list:
    if not snapshot_dir.exists():
        return []
    files = sorted(snapshot_dir.glob("*.json"))[-max_days:]
    out = []
    for f in files:
        try:
            out.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    return out


def sparkline_svg(values: list, width: int = 80, height: int = 24, color: str = "#60a5fa") -> str:
    if len(values) < 2:
        return f'<svg width="{width}" height="{height}"></svg>'
    vmin, vmax = min(values), max(values)
    rng  = max(vmax - vmin, 1)
    step = width / max(len(values) - 1, 1)
    pts  = " ".join(
        f"{i*step:.1f},{height - 2 - ((v-vmin)/rng)*(height-4):.1f}"
        for i, v in enumerate(values)
    )
    return (f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
            f'<polyline points="{pts}" fill="none" stroke="{color}" '
            f'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>')


def generate_history_html(snapshots: list) -> str:
    if not snapshots:
        return ('<div class="content"><p class="history-empty">'
                'No history yet — will appear after the first run.</p></div>')

    dates   = [s["date"] for s in snapshots]
    n_days  = len(dates)
    today   = snapshots[-1]
    yest    = snapshots[-2] if n_days >= 2 else None

    # ── Aggregate per-resource stats ──────────────────────────────────────────
    all_res   = {}   # key -> {type, label, days_listed, listing_events, scores, last_listings}
    dnsbl_freq = {}  # bl_name -> {count, resources: set}

    for snap in snapshots:
        for res_type, section in (("IP", "ips"), ("Domain", "domains")):
            for key, d in snap.get(section, {}).items():
                if key not in all_res:
                    all_res[key] = {"type": res_type, "label": d.get("label", ""),
                                    "days_listed": 0, "listing_events": 0,
                                    "scores": [], "last_listings": []}
                all_res[key]["scores"].append(d.get("score", 0))
                bls = d.get("listings", [])
                if bls:
                    all_res[key]["days_listed"]     += 1
                    all_res[key]["listing_events"]  += len(bls)
                if snap is today:
                    all_res[key]["last_listings"] = bls
                for bl in bls:
                    dnsbl_freq.setdefault(bl, {"count": 0, "resources": set()})
                    dnsbl_freq[bl]["count"] += 1
                    dnsbl_freq[bl]["resources"].add(key)

    total_events   = sum(d["listing_events"] for d in all_res.values())
    currently_listed = sum(1 for d in all_res.values() if d["last_listings"])

    # ── Changes since yesterday ───────────────────────────────────────────────
    new_list, res_list = [], []
    if yest:
        for section in ("ips", "domains"):
            for key, td in today.get(section, {}).items():
                yd       = yest.get(section, {}).get(key, {})
                t_bls, y_bls = set(td.get("listings",[])), set(yd.get("listings",[]))
                label    = td.get("label", "")
                res_type = "IP" if section == "ips" else "Domain"
                for bl in t_bls - y_bls:
                    new_list.append({"key": key, "label": label, "type": res_type, "bl": bl})
                for bl in y_bls - t_bls:
                    res_list.append({"key": key, "label": label, "type": res_type, "bl": bl})

    nc = len(new_list); rc = len(res_list)
    new_color = "#ef4444" if nc > 0 else "#22c55e"
    res_color = "#22c55e" if rc > 0 else "#94a3b8"
    cur_color = "#ef4444" if currently_listed > 0 else "#22c55e"

    overview = f"""
<div class="summary-bar" style="padding-top:1.5rem;">
  <div class="stat-card"><div class="stat-val" style="color:#60a5fa">{n_days}</div><div class="stat-label">Days Tracked</div></div>
  <div class="stat-card"><div class="stat-val" style="color:#94a3b8">{total_events}</div><div class="stat-label">Total Listing Events</div></div>
  <div class="stat-card"><div class="stat-val" style="color:{cur_color}">{currently_listed}</div><div class="stat-label">Currently Listed</div></div>
  <div class="stat-card"><div class="stat-val" style="color:{new_color}">{nc}</div><div class="stat-label">New Since Yesterday</div></div>
  <div class="stat-card"><div class="stat-val" style="color:{res_color}">{rc}</div><div class="stat-label">Resolved Since Yesterday</div></div>
</div>"""

    def _change_item(item, cls, icon):
        lbl = f' <span class="hist-pool">{item["label"]}</span>' if item["label"] else ""
        return f'<li class="{cls}">{icon} <span class="hist-mono">{item["key"]}</span>{lbl} — {item["bl"]}</li>'

    changes_html = ""
    if yest and (new_list or res_list):
        new_rows = "".join(_change_item(r, "change-new",      "🔴") for r in new_list) or "<li class='change-empty'>None</li>"
        res_rows = "".join(_change_item(r, "change-resolved", "✅") for r in res_list) or "<li class='change-empty'>None</li>"
        changes_html = f"""
<div class="history-section">
  <h3 class="history-section-title">Changes Since Last Run</h3>
  <div class="changes-grid">
    <div class="changes-col">
      <div class="changes-col-header changes-new-header">🔴 New Listings ({nc})</div>
      <ul class="changes-list">{new_rows}</ul>
    </div>
    <div class="changes-col">
      <div class="changes-col-header changes-res-header">✅ Resolved ({rc})</div>
      <ul class="changes-list">{res_rows}</ul>
    </div>
  </div>
</div>"""

    # ── Listing frequency table ───────────────────────────────────────────────
    freq_rows = sorted(
        [(k, d) for k, d in all_res.items() if d["days_listed"] > 0],
        key=lambda x: (-x[1]["days_listed"], x[0])
    )
    freq_html = ""
    for key, d in freq_rows:
        pct  = round(d["days_listed"] / n_days * 100)
        bls  = d["last_listings"]
        icon = "🔴" if bls else "✅"
        cur  = "".join(f'<span class="hist-bl-tag">{bl}</span>' for bl in bls) or '<span class="hist-clean">Clean today</span>'
        freq_html += (
            f'<tr><td class="hist-resource">{icon} <span class="hist-mono">{key}</span></td>'
            f'<td class="hist-pool-cell">{d["label"]}</td>'
            f'<td class="hist-type-cell">{d["type"]}</td>'
            f'<td class="hist-days">{d["days_listed"]}/{n_days} <span class="hist-pct">({pct}%)</span>'
            f'  <div class="hist-bar"><div class="hist-bar-fill" style="width:{max(pct,2)}%"></div></div></td>'
            f'<td>{cur}</td></tr>'
        )
    freq_table = f"""
<div class="history-section">
  <h3 class="history-section-title">Listing Frequency — All Time</h3>
  <table class="hist-table">
    <thead><tr><th>Resource</th><th>Pool</th><th>Type</th><th>Days Listed</th><th>Active Listings</th></tr></thead>
    <tbody>{freq_html}</tbody>
  </table>
</div>""" if freq_html else ""

    # ── DNSBL hit frequency ───────────────────────────────────────────────────
    bl_rows = "".join(
        f'<tr><td class="hist-bl-name">{bl}</td>'
        f'<td class="hist-count">{d["count"]}</td>'
        f'<td class="hist-count">{len(d["resources"])}</td></tr>'
        for bl, d in sorted(dnsbl_freq.items(), key=lambda x: -x[1]["count"])
    )
    dnsbl_table = f"""
<div class="history-section">
  <h3 class="history-section-title">Blacklist Hit Frequency</h3>
  <table class="hist-table" style="max-width:600px">
    <thead><tr><th>Blacklist</th><th>Total Hits</th><th>Unique Resources</th></tr></thead>
    <tbody>{bl_rows}</tbody>
  </table>
</div>""" if bl_rows else ""

    # ── Score sparklines ──────────────────────────────────────────────────────
    def _spark_card(key, d):
        scores = d["scores"]
        latest = scores[-1] if scores else 0
        color  = score_color(latest)
        spark  = sparkline_svg(scores, color=color)
        mono   = ' style="font-family:monospace;font-size:0.7rem"' if d["type"] == "IP" else ""
        return (f'<div class="hist-spark-card">'
                f'<div class="hist-spark-name"{mono}>{key}</div>'
                f'<div class="hist-spark-pool">{d["label"] or "—"}</div>'
                f'<div class="hist-spark-chart">{spark}</div>'
                f'<div class="hist-spark-score" style="color:{color}">{latest}</div>'
                f'</div>')

    dom_cards = "".join(_spark_card(k, d) for k, d in sorted(all_res.items()) if d["type"] == "Domain")
    ip_cards  = "".join(_spark_card(k, d) for k, d in sorted(all_res.items()) if d["type"] == "IP")

    trends_html = ""
    if dom_cards:
        trends_html += f'<div class="hist-spark-group-title">Domains</div><div class="hist-spark-grid">{dom_cards}</div>'
    if ip_cards:
        trends_html += f'<div class="hist-spark-group-title">IPs</div><div class="hist-spark-grid">{ip_cards}</div>'

    trends_section = f"""
<div class="history-section">
  <h3 class="history-section-title">Score Trends ({n_days} day{"s" if n_days != 1 else ""})</h3>
  {trends_html}
</div>""" if trends_html else ""

    date_range = f'Tracking {dates[0]} → {dates[-1]}'
    return f"""
<div class="pool-nav">
  <span class="pool-nav-label">{date_range}</span>
</div>
<div class="content">
  {overview}
  {changes_html}
  {freq_table}
  {dnsbl_table}
  {trends_section}
</div>"""


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

    label_safe = label.replace('"', '&quot;')
    return f"""
<div class="ip-card domain-card" id="{card_id}" data-status="{status}" data-resource="{domain}" data-label="{label_safe}">
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

def render_abuseipdb_panel(abip: dict) -> str:
    if not abip.get("available"):
        if abip.get("error"):
            return f'<div class="abip-panel abip-error"><span class="abip-logo">AbuseIPDB</span> Error: {abip["error"]}</div>'
        return ""
    score     = abip["score"]
    bar_color = "#22c55e" if score < 10 else ("#f59e0b" if score < 40 else "#ef4444")
    rep_str   = f"{score}% abuse confidence"
    reports   = abip["total_reports"]
    last      = f" &nbsp;·&nbsp; Last reported {abip['last_reported']}" if abip["last_reported"] else ""
    usage     = f'<div class="abip-usage">Usage type: <span>{abip["usage_type"]}</span></div>' if abip["usage_type"] else ""
    wl        = ' <span class="abip-wl">✓ Whitelisted</span>' if abip["is_whitelisted"] else ""
    return f"""
<div class="abip-panel">
  <div class="abip-header">
    <span class="abip-logo">AbuseIPDB</span>
    <span class="abip-meta">{reports} report{"s" if reports != 1 else ""}{last}</span>
    <span class="abip-score" style="color:{bar_color}">{rep_str}{wl}</span>
  </div>
  <div class="abip-bar-wrap">
    <div class="abip-bar"><div class="abip-fill" style="width:{score}%;background:{bar_color}"></div></div>
  </div>
  {usage}
</div>"""


def render_ip_card(result: dict, card_id: str) -> str:
    ip    = result["ip"]
    info  = result["info"]
    score = result["score"]
    color = score_color(score)

    vt_panel    = render_vt_panel(result["vt"])
    abip_panel  = render_abuseipdb_panel(result.get("abuseipdb", {}))
    listing_sec = render_listing_alert(result["listings"], "DNSBL")
    dnsbl_rows  = "".join(render_dnsbl_row(r) for r in result["all_results"])
    label       = result.get("label", "")

    label_safe = label.replace('"', '&quot;')
    return f"""
<div class="ip-card" id="{card_id}" data-status="{result['status']}" data-resource="{ip}" data-label="{label_safe}">
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
  {abip_panel}
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

def _render_run_meta_bar(meta: dict) -> str:
    if not meta:
        return ""
    dur   = meta.get("duration_s", 0)
    derr  = meta.get("dnsbl_error_count", 0)
    verr  = meta.get("vt_error_count", 0)
    quick = meta.get("quick_mode", False)
    dur_str  = f"{dur:.0f}s" if dur < 60 else f"{dur/60:.1f}m"
    derr_cls = "run-meta-ok" if derr == 0 else ("run-meta-warn" if derr < 10 else "run-meta-err")
    verr_cls = "run-meta-ok" if verr == 0 else "run-meta-warn"
    quick_tag = ' &nbsp;·&nbsp; <span class="run-meta-warn">⚡ quick mode (VT skipped)</span>' if quick else ""
    return (f'<div class="run-meta-bar">'
            f'<span>⏱ Completed in {dur_str}</span>'
            f'<span class="run-meta-sep">·</span>'
            f'<span class="{derr_cls}">{derr} DNSBL check error{"s" if derr != 1 else ""}</span>'
            f'<span class="run-meta-sep">·</span>'
            f'<span class="{verr_cls}">{verr} VT error{"s" if verr != 1 else ""}</span>'
            f'{quick_tag}</div>')


def generate_html(domain_groups: list, ip_groups: list, generated_at: datetime.datetime,
                  snapshots: list = None, run_meta: dict = None) -> str:
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

    /* AbuseIPDB panel */
    .abip-panel {{ margin: 1rem 1.5rem 0; background: #0f1e35; border: 1px solid #1e3a5f; border-left: 4px solid #8b5cf6; border-radius: 8px; padding: 0.875rem 1.25rem; }}
    .abip-panel.abip-error {{ color: #94a3b8; font-size: 0.82rem; }}
    .abip-header {{ display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.5rem; }}
    .abip-logo {{ font-weight: 700; font-size: 0.82rem; color: #a78bfa; letter-spacing: 0.02em; }}
    .abip-meta {{ font-size: 0.72rem; color: #64748b; }}
    .abip-score {{ font-size: 0.78rem; font-weight: 600; margin-left: auto; }}
    .abip-wl {{ color: #22c55e; font-weight: 500; margin-left: 0.4rem; }}
    .abip-bar {{ height: 9px; border-radius: 999px; background: #1e293b; overflow: hidden; margin-bottom: 0.3rem; }}
    .abip-fill {{ height: 100%; border-radius: 999px; }}
    .abip-usage {{ font-size: 0.72rem; color: #64748b; margin-top: 0.3rem; }}
    .abip-usage span {{ color: #94a3b8; }}

    /* Filter bar */
    .filter-bar {{ display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 2rem; background: #0a1120; border-bottom: 1px solid #1e293b; flex-wrap: wrap; }}
    .filter-label {{ font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; white-space: nowrap; }}
    .filter-status-btns {{ display: flex; gap: 0.35rem; flex-wrap: wrap; }}
    .filter-btn {{ padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.75rem; font-weight: 500; background: #1e293b; border: 1px solid #334155; color: #94a3b8; cursor: pointer; transition: all 0.15s; white-space: nowrap; }}
    .filter-btn:hover {{ border-color: #60a5fa; color: #60a5fa; }}
    .filter-btn.active {{ background: #1e3a5f; border-color: #60a5fa; color: #93c5fd; }}
    .filter-clean.active  {{ background: #052e16; border-color: #166534; color: #4ade80; }}
    .filter-warn.active   {{ background: #1c1009; border-color: #78350f; color: #fbbf24; }}
    .filter-danger.active {{ background: #1a0505; border-color: #7f1d1d; color: #fca5a5; }}
    .filter-search {{ flex: 1; min-width: 200px; max-width: 320px; padding: 0.3rem 0.75rem; background: #1e293b; border: 1px solid #334155; border-radius: 999px; color: #e2e8f0; font-size: 0.8rem; outline: none; }}
    .filter-search:focus {{ border-color: #60a5fa; }}
    .filter-search::placeholder {{ color: #475569; }}
    .filter-count {{ font-size: 0.72rem; color: #64748b; white-space: nowrap; margin-left: auto; }}

    /* Run metadata bar */
    .run-meta-bar {{ display: flex; align-items: center; gap: 0.5rem; padding: 0.45rem 2rem; background: #0a1120; border-bottom: 1px solid #1e293b; font-size: 0.72rem; color: #475569; flex-wrap: wrap; }}
    .run-meta-sep {{ color: #1e293b; }}
    .run-meta-ok  {{ color: #22c55e; }}
    .run-meta-warn {{ color: #f59e0b; }}
    .run-meta-err  {{ color: #ef4444; }}

    /* History tab */
    .history-empty {{ color: #64748b; font-style: italic; padding: 2rem; }}
    .history-section {{ margin-bottom: 2.5rem; }}
    .history-section-title {{ font-size: 1rem; font-weight: 700; color: #f1f5f9; margin-bottom: 1rem; padding-bottom: 0.4rem; border-bottom: 1px solid #1e293b; }}
    .changes-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
    @media (max-width: 700px) {{ .changes-grid {{ grid-template-columns: 1fr; }} }}
    .changes-col {{ background: #1e293b; border-radius: 10px; border: 1px solid #334155; overflow: hidden; }}
    .changes-col-header {{ padding: 0.6rem 1rem; font-size: 0.8rem; font-weight: 600; border-bottom: 1px solid #334155; }}
    .changes-new-header {{ background: #1a0505; color: #fca5a5; }}
    .changes-res-header {{ background: #052e16; color: #86efac; }}
    .changes-list {{ list-style: none; padding: 0.5rem 0; max-height: 260px; overflow-y: auto; }}
    .changes-list li {{ padding: 0.3rem 1rem; font-size: 0.8rem; color: #cbd5e1; border-bottom: 1px solid #1e293b; }}
    .changes-list li:last-child {{ border-bottom: none; }}
    .change-empty {{ color: #475569 !important; font-style: italic; }}
    .hist-mono {{ font-family: monospace; font-size: 0.8rem; }}
    .hist-pool {{ color: #64748b; font-size: 0.75rem; }}
    .hist-table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
    .hist-table th {{ text-align: left; color: #64748b; font-weight: 600; font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.4rem 0.75rem; border-bottom: 1px solid #334155; background: #162032; }}
    .hist-table td {{ padding: 0.4rem 0.75rem; border-bottom: 1px solid #1e293b; vertical-align: middle; }}
    .hist-table tr:last-child td {{ border-bottom: none; }}
    .hist-table tr:hover td {{ background: #162032; }}
    .hist-resource {{ white-space: nowrap; }}
    .hist-pool-cell {{ color: #64748b; font-size: 0.78rem; }}
    .hist-type-cell {{ color: #94a3b8; font-size: 0.78rem; }}
    .hist-days {{ font-size: 0.8rem; color: #cbd5e1; min-width: 160px; }}
    .hist-pct {{ color: #64748b; font-size: 0.72rem; }}
    .hist-bar {{ height: 5px; background: #1e293b; border-radius: 999px; margin-top: 0.25rem; overflow: hidden; max-width: 120px; }}
    .hist-bar-fill {{ height: 100%; background: #3b82f6; border-radius: 999px; }}
    .hist-bl-tag {{ display: inline-block; background: #1a0505; color: #fca5a5; border: 1px solid #7f1d1d; border-radius: 4px; font-size: 0.68rem; padding: 0.1rem 0.4rem; margin: 0.1rem 0.15rem; }}
    .hist-clean {{ color: #22c55e; font-size: 0.78rem; }}
    .hist-bl-name {{ color: #cbd5e1; font-weight: 500; }}
    .hist-count {{ text-align: center; color: #94a3b8; }}
    .hist-spark-group-title {{ font-size: 0.78rem; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.06em; margin: 1.25rem 0 0.6rem; }}
    .hist-spark-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 0.75rem; }}
    .hist-spark-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 0.75rem; display: flex; flex-direction: column; gap: 0.3rem; }}
    .hist-spark-name {{ font-size: 0.72rem; color: #cbd5e1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .hist-spark-pool {{ font-size: 0.65rem; color: #475569; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    .hist-spark-chart {{ line-height: 0; }}
    .hist-spark-score {{ font-size: 0.9rem; font-weight: 700; }}

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

{_render_run_meta_bar(run_meta)}

<div class="tab-bar">
  <button class="tab-btn active" onclick="switchTab('domains', this)">
    Domains <span class="tab-count">{len(all_domains)}</span>
  </button>
  <button class="tab-btn" onclick="switchTab('ips', this)">
    IP Pools <span class="tab-count">{len(all_ips)}</span>
  </button>
  <button class="tab-btn" onclick="switchTab('history', this)">
    History <span class="tab-count">{len(snapshots) if snapshots else 0}</span>
  </button>
</div>

<div class="filter-bar" id="filter-bar">
  <span class="filter-label">Filter:</span>
  <div class="filter-status-btns">
    <button class="filter-btn active" data-status="" onclick="setStatusFilter(this)">All</button>
    <button class="filter-btn filter-clean"  data-status="clean"   onclick="setStatusFilter(this)">✅ Clean</button>
    <button class="filter-btn filter-warn"   data-status="warning" onclick="setStatusFilter(this)">⚠ Warning</button>
    <button class="filter-btn filter-danger" data-status="danger"  onclick="setStatusFilter(this)">🔴 Blacklisted</button>
  </div>
  <input class="filter-search" id="filter-search" type="text" placeholder="Search IP, domain, or pool…" oninput="applyFilter()">
  <span class="filter-count" id="filter-count"></span>
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

<div id="tab-history" class="tab-panel">
  {generate_history_html(snapshots or [])}
</div>

<script>
  let _activeStatus = '';

  function switchTab(name, btn) {{
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    btn.classList.add('active');
    const filterBar = document.getElementById('filter-bar');
    if (filterBar) filterBar.style.display = name === 'history' ? 'none' : '';
    // Reset filter state on tab switch
    _activeStatus = '';
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    const allBtn = document.querySelector('.filter-btn[data-status=""]');
    if (allBtn) allBtn.classList.add('active');
    const searchEl = document.getElementById('filter-search');
    if (searchEl) searchEl.value = '';
    const countEl = document.getElementById('filter-count');
    if (countEl) countEl.textContent = '';
    // Show all cards in new tab
    document.querySelectorAll('[data-resource]').forEach(c => c.style.display = '');
    document.querySelectorAll('.pool-section').forEach(p => p.style.display = '');
    window.scrollTo({{top: 0, behavior: 'smooth'}});
  }}

  function setStatusFilter(btn) {{
    _activeStatus = btn.dataset.status;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilter();
  }}

  function applyFilter() {{
    const search = (document.getElementById('filter-search').value || '').toLowerCase().trim();
    const activeTab = document.querySelector('.tab-panel.active');
    if (!activeTab || activeTab.id === 'tab-history') return;
    let visible = 0, total = 0;
    activeTab.querySelectorAll('[data-resource]').forEach(card => {{
      total++;
      const matchStatus = !_activeStatus || card.dataset.status === _activeStatus;
      const matchSearch = !search ||
        card.dataset.resource.toLowerCase().includes(search) ||
        (card.dataset.label || '').toLowerCase().includes(search);
      const show = matchStatus && matchSearch;
      card.style.display = show ? '' : 'none';
      if (show) visible++;
    }});
    activeTab.querySelectorAll('.pool-section').forEach(pool => {{
      const any = [...pool.querySelectorAll('[data-resource]')].some(c => c.style.display !== 'none');
      pool.style.display = any ? '' : 'none';
    }});
    const countEl = document.getElementById('filter-count');
    if (countEl) countEl.textContent = (search || _activeStatus) ? `${{visible}} / ${{total}} shown` : '';
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


def load_from_csv(csv_path: Path, key: str) -> list[dict]:
    import csv
    entries = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            val = row.get(key, "").strip()
            if val:
                entries.append({key: val, "label": (row.get("label") or "").strip()})
    return entries


def write_data_json(repo_dir: Path, domain_groups: list, ip_groups: list,
                    generated_at: datetime.datetime, run_meta: dict = None):
    domains_out = []
    for _, group in domain_groups:
        for r in group:
            vt = r.get("vt", {})
            domains_out.append({
                "domain":       r["domain"],
                "label":        r.get("label", ""),
                "score":        r["score"],
                "status":       r["status"],
                "listed_count": r["listed_count"],
                "listings":     [x["name"] for x in r["listings"]],
                "vt_malicious": vt.get("malicious") if vt.get("available") else None,
                "vt_suspicious":vt.get("suspicious") if vt.get("available") else None,
            })
    ips_out = []
    for _, group in ip_groups:
        for r in group:
            vt   = r.get("vt", {})
            abip = r.get("abuseipdb", {})
            ips_out.append({
                "ip":             r["ip"],
                "label":          r.get("label", ""),
                "score":          r["score"],
                "status":         r["status"],
                "listed_count":   r["listed_count"],
                "listings":       [x["name"] for x in r["listings"]],
                "vt_malicious":   vt.get("malicious")  if vt.get("available") else None,
                "vt_suspicious":  vt.get("suspicious") if vt.get("available") else None,
                "abuseipdb_score":abip.get("score")    if abip.get("available") else None,
            })
    all_results = domains_out + ips_out
    payload = {
        "generated_at":   generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run_duration_s": round(run_meta.get("duration_s", 0), 1) if run_meta else None,
        "quick_mode":     run_meta.get("quick_mode", False) if run_meta else False,
        "summary": {
            "total":   len(all_results),
            "clean":   sum(1 for r in all_results if r["status"] == "clean"),
            "warning": sum(1 for r in all_results if r["status"] == "warning"),
            "danger":  sum(1 for r in all_results if r["status"] == "danger"),
        },
        "domains": domains_out,
        "ips":     ips_out,
    }
    (repo_dir / "data.json").write_text(
        json.dumps(payload, separators=(",", ":")), encoding="utf-8"
    )


def publish_to_github(repo_dir: Path, latest_path: Path, now: datetime.datetime,
                      slack_url: str = ""):
    import subprocess

    index_path = repo_dir / "index.html"
    index_path.write_text(latest_path.read_text(encoding="utf-8"), encoding="utf-8")

    def git(args: list[str]) -> tuple[int, str]:
        r = subprocess.run(["git", "-C", str(repo_dir)] + args,
                           capture_output=True, text=True)
        return r.returncode, (r.stdout + r.stderr).strip()

    git(["add", "index.html"])
    git(["add", "snapshots/"])
    git(["add", "data.json"])
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
        msg = f"  GitHub Pages: push failed — {out}"
        print(msg)
        send_slack_alert(slack_url, f"🔴 *Reputation checker — GitHub push failed*\n```{out[:400]}```")


def main():
    import sys, traceback
    args         = set(sys.argv[1:])
    domains_only = "--domains-only" in args
    ips_only     = "--ips-only"     in args
    quick_mode   = "--quick"        in args

    script_dir = Path(__file__).parent
    with open(script_dir / "config.json") as f:
        config = json.load(f)

    slack_url      = config.get("slack_webhook_url", "")
    vt_key         = config.get("virustotal_api_key", "")
    dqs_key        = config.get("spamhaus_dqs_key", "")
    abuseipdb_key  = config.get("abuseipdb_api_key", "")
    timeout        = config.get("timeout_seconds", 10)
    report_dir     = script_dir / config.get("report_dir", "reports")
    report_dir.mkdir(exist_ok=True)

    # ── Load IPs and domains — CSV takes priority over config.json ───────────
    ips_csv     = script_dir / "ips.csv"
    domains_csv = script_dir / "domains.csv"

    if not domains_only:
        ip_entries = (load_from_csv(ips_csv, "ip") if ips_csv.exists()
                      else parse_ip_entries(config.get("ips", [])))
    else:
        ip_entries = []

    if not ips_only:
        domain_entries = (load_from_csv(domains_csv, "domain") if domains_csv.exists()
                          else parse_domain_entries(config.get("domains", [])))
    else:
        domain_entries = []

    try:
        _run(config, ip_entries, domain_entries, slack_url, vt_key, dqs_key,
             abuseipdb_key, timeout, report_dir, script_dir, skip_vt=quick_mode)
    except Exception:
        tb = traceback.format_exc()
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        send_slack_alert(slack_url,
            f"🔴 *Reputation checker crashed* — {now_str}\n```{tb[-600:]}```")
        raise


def _run(config, ip_entries, domain_entries, slack_url, vt_key, dqs_key,
         abuseipdb_key, timeout, report_dir, script_dir, skip_vt: bool = False):

    run_start = time.monotonic()

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

    now_str   = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    dnsbl_src = f"{len(IP_DNSBLS)} IP DNSBLs + {len(DOMAIN_DNSBLS)} domain DNSBLs"
    print(f"IP & Domain Reputation Checker — {now_str}")
    print(f"  {len(unique_ips)} unique IPs  |  {len(unique_domains)} domains  |  {dnsbl_src}")
    if abuseipdb_key:
        print(f"  AbuseIPDB: {len(unique_ips)} IP checks (parallel)")
    if vt_key:
        est = round(total_vt * VT_INTERVAL / 60, 1)
        print(f"  VirusTotal: {total_vt} resources → ~{est} min (rate-limited)\n")

    # ── Phase 1: DNSBL + geo + AbuseIPDB — parallel ───────────────────────────
    print("Phase 1: DNSBL + DNS checks (parallel)...")
    ip_data:     dict[str, dict] = {}
    domain_data: dict[str, dict] = {}
    abip_data:   dict[str, dict] = {}

    workers = min(len(unique_ips) + len(unique_domains) + len(unique_ips if abuseipdb_key else []), 20)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        ip_futures   = {ex.submit(check_ip_dnsbl_geo,         ip,  timeout): ("ip",   ip)  for ip  in unique_ips}
        dom_futures  = {ex.submit(check_domain_dnsbl_and_dns, dom, timeout): ("dom",  dom) for dom in unique_domains}
        abip_futures = ({ex.submit(fetch_abuseipdb, ip, abuseipdb_key, timeout): ("abip", ip) for ip in unique_ips}
                        if abuseipdb_key else {})
        all_futures  = {**ip_futures, **dom_futures, **abip_futures}
        for future in concurrent.futures.as_completed(all_futures):
            kind, key = all_futures[future]
            result    = future.result()
            if kind == "ip":
                ip_data[key] = result
                print(f"  IP  {key}: {result['listed_count']} DNSBL listings", flush=True)
            elif kind == "dom":
                domain_data[key] = result
                print(f"  DOM {key}: {result['listed_count']} listings", flush=True)
            else:
                abip_data[key] = result

    for ip, abip in abip_data.items():
        if ip in ip_data:
            ip_data[ip]["abuseipdb"] = abip

    # ── Spamhaus alert — fires immediately after DNSBL results ────────────────
    if slack_url:
        sh_hits = []
        for ip, data in ip_data.items():
            hits = [r["name"] for r in data["listings"] if r["category"] == "Spamhaus"]
            if hits:
                sh_hits.append(f"IP {ip}: {', '.join(hits)}")
        for dom, data in domain_data.items():
            hits = [r["name"] for r in data["listings"] if r["category"] == "Spamhaus"]
            if hits:
                sh_hits.append(f"Domain {dom}: {', '.join(hits)}")
        if sh_hits:
            send_slack_alert(slack_url,
                f"🚨 *Spamhaus listing detected* — {now_str}\n" +
                "\n".join(f"• {h}" for h in sh_hits))

    # ── Phase 2: VirusTotal — sequential, rate-limited ────────────────────────
    vt_error_count = 0
    if vt_key and not skip_vt:
        total_vt_checks = len(unique_ips) + len(unique_domains)
        print(f"\nPhase 2: VirusTotal ({total_vt_checks} checks, ~{VT_INTERVAL}s apart)...")
        idx = 1
        for domain in unique_domains:
            print(f"  [{idx}/{total_vt_checks}] {domain} VT...", end=" ", flush=True)
            vt = fetch_virustotal(domain, "domains", vt_key, timeout)
            domain_data[domain]["vt"] = vt
            if not vt["available"]:
                vt_error_count += 1
            print(f"{vt['malicious']}M/{vt['suspicious']}S" if vt["available"] else f"error: {vt['error']}", flush=True)
            idx += 1
        for ip in unique_ips:
            print(f"  [{idx}/{total_vt_checks}] {ip} VT...", end=" ", flush=True)
            vt = fetch_virustotal(ip, "ip_addresses", vt_key, timeout)
            ip_data[ip]["vt"] = vt
            if not vt["available"]:
                vt_error_count += 1
            print(f"{vt['malicious']}M/{vt['suspicious']}S" if vt["available"] else f"error: {vt['error']}", flush=True)
            idx += 1
    elif skip_vt:
        print("\nPhase 2: VirusTotal skipped (--quick mode)")

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

    # ── Snapshot — save today's data, load history ────────────────────────────
    now          = datetime.datetime.now(datetime.timezone.utc)
    snapshot_dir = script_dir / "snapshots"
    save_snapshot(snapshot_dir, now, ip_data, domain_data, ip_entries, domain_entries)
    snapshots = load_snapshots(snapshot_dir)
    print(f"  Snapshots: {len(snapshots)} day(s) of history saved")

    # ── Build run metadata ─────────────────────────────────────────────────────
    dnsbl_error_count = sum(r["error_count"] for r in ip_data.values()) + \
                        sum(r["error_count"] for r in domain_data.values())
    run_meta = {
        "duration_s":        time.monotonic() - run_start,
        "dnsbl_error_count": dnsbl_error_count,
        "vt_error_count":    vt_error_count,
        "quick_mode":        skip_vt,
    }

    # ── Write data.json API file ───────────────────────────────────────────────
    write_data_json(script_dir, domain_groups, ip_groups, now, run_meta)

    # ── Generate report ────────────────────────────────────────────────────────
    html        = generate_html(domain_groups, ip_groups, now, snapshots, run_meta)
    latest_path = report_dir / "latest.html"
    dated_path  = report_dir / f"report_{now.strftime('%Y%m%d_%H%M%S')}.html"
    latest_path.write_text(html, encoding="utf-8")
    dated_path.write_text(html, encoding="utf-8")

    print(f"\nReport saved:")
    print(f"  Latest : {latest_path}")
    print(f"  Archive: {dated_path}")

    # ── Publish to GitHub Pages ────────────────────────────────────────────────
    publish_to_github(script_dir, latest_path, now, slack_url)

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
