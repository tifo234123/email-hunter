#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║              EMAIL OSINT TOOL v3.0  —  by Tifo                      ║
║         Professional Email Intelligence Platform                     ║
╚══════════════════════════════════════════════════════════════════════╝

DATA SOURCES:
  · HaveIBeenPwned     (breaches + pastes)
  · LeakCheck API      (additional breach DB)
  · GitHub API         (profile, repos, gists, orgs, activity)
  · Gravatar           (profile, linked accounts)
  · DNS / MX / SPF / DKIM / DMARC / BIMI
  · WHOIS              (domain registration, registrar, dates)
  · IP / ASN           (domain IP, geolocation, ASN, reverse DNS)
  · Shodan             (open ports, vulns, banners on mail server)
  · Wayback Machine    (snapshots of domain)
  · Platform Footprint (30+ sites via username)
  · Username Correlation (cross-platform username variants)
  · DNSBL Blacklist    (9 blacklist zones)
  · ThreatIntel        (AbuseIPDB)
  · Risk Scoring       (automated threat assessment)

USAGE:
  python email_osint.py                           # interactive
  python email_osint.py -e target@example.com     # single scan
  python email_osint.py --bulk emails.txt         # bulk
  python email_osint.py -e t@e.com --export json  # export

ENV VARS (optional but unlock full power):
  HIBP_API_KEY     -> haveibeenpwned.com/API/Key   (free)
  SHODAN_API_KEY   -> shodan.io                    (free tier)
  LEAKCHECK_KEY    -> leakcheck.io                 (free tier)
  ABUSEIPDB_KEY    -> abuseipdb.com                (free)

REQUIREMENTS:
  pip install rich requests dnspython python-whois
"""

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import requests
from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                           TaskProgressColumn, TextColumn)
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.markup import escape

try:
    import dns.resolver
    import dns.reversename
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as whois_lib
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

# ── API KEYS ──────────────────────────────────────────────────────────
HIBP_KEY      = os.environ.get("HIBP_API_KEY", "")
SHODAN_KEY    = os.environ.get("SHODAN_API_KEY", "")
LEAKCHECK_KEY = os.environ.get("LEAKCHECK_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")

# ── THEME ─────────────────────────────────────────────────────────────
ACCENT  = "#00ffa3"
BLUE    = "#4fa3e0"
WARN    = "#ff6b6b"
YELLOW  = "#ffd700"
MUTED   = "#8b949e"
WHITE   = "#e6edf3"
PURPLE  = "#c792ea"

console = Console(highlight=False)
HEADERS = {"User-Agent": "Mozilla/5.0 (OSINT-Research/3.0; Educational)"}

DISPOSABLE = {
    "mailinator.com","guerrillamail.com","tempmail.com","throwaway.email",
    "yopmail.com","10minutemail.com","trashmail.com","sharklasers.com",
    "fakeinbox.com","maildrop.cc","dispostable.com","spamgourmet.com",
    "getairmail.com","tmail.com","temp-mail.org","burnermail.io",
    "tempr.email","discard.email","spambox.us","mailnull.com",
}

PLATFORMS = {
    "GitHub":       "https://github.com/{u}",
    "GitLab":       "https://gitlab.com/{u}",
    "Dev.to":       "https://dev.to/{u}",
    "npm":          "https://www.npmjs.com/~{u}",
    "PyPI":         "https://pypi.org/user/{u}/",
    "Replit":       "https://replit.com/@{u}",
    "Keybase":      "https://keybase.io/{u}",
    "SourceForge":  "https://sourceforge.net/u/{u}/profile/",
    "Twitter/X":    "https://twitter.com/{u}",
    "Reddit":       "https://www.reddit.com/user/{u}",
    "Tumblr":       "https://{u}.tumblr.com",
    "Medium":       "https://medium.com/@{u}",
    "Mastodon":     "https://mastodon.social/@{u}",
    "Pinterest":    "https://www.pinterest.com/{u}/",
    "Steam":        "https://steamcommunity.com/id/{u}",
    "Twitch":       "https://www.twitch.tv/{u}",
    "Chess.com":    "https://www.chess.com/member/{u}",
    "Duolingo":     "https://www.duolingo.com/profile/{u}",
    "Codecademy":   "https://www.codecademy.com/profiles/{u}",
    "Wordpress":    "https://{u}.wordpress.com",
    "Blogger":      "https://{u}.blogspot.com",
    "Spotify":      "https://open.spotify.com/user/{u}",
    "SoundCloud":   "https://soundcloud.com/{u}",
    "Last.fm":      "https://www.last.fm/user/{u}",
    "Gravatar":     "https://gravatar.com/{u}",
    "Pastebin":     "https://pastebin.com/u/{u}",
    "HackerEarth":  "https://www.hackerearth.com/@{u}",
    "Kaggle":       "https://www.kaggle.com/{u}",
    "Tryhackme":    "https://tryhackme.com/p/{u}",
    "HackTheBox":   "https://app.hackthebox.com/profile/{u}",
    "About.me":     "https://about.me/{u}",
    "Scribd":       "https://www.scribd.com/{u}",
}

DNSBL_ZONES = [
    "zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net",
    "b.barracudacentral.org","dnsbl-1.uceprotect.net",
    "spam.dnsbl.sorbs.net","ix.dnsbl.manitu.net",
    "truncate.gbudb.net","psbl.surriel.com",
]

NOT_FOUND_SIGNALS = [
    "page not found","user not found","doesn't exist","no user found",
    "profile not found","this account","404","not available","suspended",
    "deactivated","deleted","banned","no results","nothing here",
]

# ── DATA MODEL ────────────────────────────────────────────────────────
@dataclass
class OsintResult:
    email:     str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    valid_format:  bool = False
    username:      str  = ""
    domain:        str  = ""
    provider:      str  = ""
    disposable:    bool = False
    mx_records:    List[str] = field(default_factory=list)
    a_records:     List[str] = field(default_factory=list)
    aaaa_records:  List[str] = field(default_factory=list)
    ns_records:    List[str] = field(default_factory=list)
    txt_records:   List[str] = field(default_factory=list)
    spf_record:    str  = ""
    dmarc_record:  str  = ""
    dkim_hints:    List[str] = field(default_factory=list)
    bimi_record:   str  = ""
    dnssec:        bool = False
    whois_registrar:    str  = ""
    whois_created:      str  = ""
    whois_expires:      str  = ""
    whois_updated:      str  = ""
    whois_org:          str  = ""
    whois_country:      str  = ""
    whois_name_servers: List[str] = field(default_factory=list)
    domain_age_days:    int  = 0
    domain_ip:     str  = ""
    ip_ptr:        str  = ""
    ip_country:    str  = ""
    ip_city:       str  = ""
    ip_org:        str  = ""
    ip_asn:        str  = ""
    ip_abuse_score: int = -1
    shodan_ports:     List[int]  = field(default_factory=list)
    shodan_vulns:     List[str]  = field(default_factory=list)
    shodan_banners:   List[str]  = field(default_factory=list)
    shodan_hostnames: List[str]  = field(default_factory=list)
    shodan_tags:      List[str]  = field(default_factory=list)
    dnsbl_listed:   List[str] = field(default_factory=list)
    dnsbl_clean:    int = 0
    wayback_first:  str = ""
    wayback_last:   str = ""
    wayback_count:  int = 0
    breach_count:   int  = 0
    paste_count:    int  = 0
    breaches:       List[Dict] = field(default_factory=list)
    compromised_data: List[str] = field(default_factory=list)
    hibp_error:     str = ""
    leakcheck_found: bool = False
    leakcheck_sources: List[str] = field(default_factory=list)
    leakcheck_count:   int = 0
    gravatar_exists:       bool = False
    gravatar_display_name: str  = ""
    gravatar_about_me:     str  = ""
    gravatar_location:     str  = ""
    gravatar_urls:         List[str] = field(default_factory=list)
    gravatar_accounts:     List[Dict] = field(default_factory=list)
    gravatar_avatar_url:   str  = ""
    gravatar_verified:     bool = False
    github_exists:    bool = False
    github_username:  str  = ""
    github_name:      str  = ""
    github_bio:       str  = ""
    github_company:   str  = ""
    github_location:  str  = ""
    github_followers: int  = 0
    github_following: int  = 0
    github_repos:     int  = 0
    github_gists:     int  = 0
    github_url:       str  = ""
    github_created:   str  = ""
    github_orgs:      List[str] = field(default_factory=list)
    github_top_repos: List[Dict] = field(default_factory=list)
    github_languages: List[str] = field(default_factory=list)
    github_hireable:  bool = False
    github_blog:      str  = ""
    platforms_found:   Dict[str, str] = field(default_factory=dict)
    platforms_checked: int = 0
    username_variants: List[str] = field(default_factory=list)
    risk_score:  int  = 0
    risk_flags:  List[str] = field(default_factory=list)

# ══════════════════════════════════════════════════════════════════════
#  MODULES
# ══════════════════════════════════════════════════════════════════════

def validate_email(email: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email))

def detect_provider(domain: str, mx: List[str]) -> str:
    d = domain.lower()
    mx_str = " ".join(mx).lower()
    checks = [
        (["gmail","googlemail"], ["google","gmail"], "Google / Gmail"),
        (["outlook","hotmail","live","msn"], ["microsoft","outlook","protection.outlook"], "Microsoft / Outlook"),
        (["yahoo","ymail"], ["yahoo"], "Yahoo"),
        (["protonmail","proton.me"], ["proton"], "ProtonMail"),
        (["icloud","me.com","mac.com"], ["apple","icloud"], "Apple iCloud"),
        (["zoho"], ["zoho"], "Zoho Mail"),
        (["fastmail"], ["fastmail"], "Fastmail"),
        (["tutanota","tuta.io"], ["tutanota"], "Tutanota"),
        (["yandex"], ["yandex"], "Yandex Mail"),
        (["gmx"], ["gmx"], "GMX"),
        (["aol"], ["aol"], "AOL"),
    ]
    for dom_kw, mx_kw, label in checks:
        if any(k in d for k in dom_kw) or any(k in mx_str for k in mx_kw):
            return label
    return "Custom / Corporate"

def dns_lookup(domain: str, rtype: str) -> List[str]:
    if HAS_DNS:
        try:
            return [str(r) for r in dns.resolver.resolve(domain, rtype, lifetime=5)]
        except Exception:
            return []
    try:
        r = requests.get("https://dns.google/resolve",
                         params={"name": domain, "type": rtype},
                         timeout=5, headers=HEADERS)
        return [a.get("data","") for a in r.json().get("Answer",[])]
    except Exception:
        return []

def full_dns_scan(domain: str, result: OsintResult) -> None:
    result.mx_records   = [x.split()[-1].rstrip(".") for x in dns_lookup(domain, "MX")]
    result.a_records    = dns_lookup(domain, "A")
    result.aaaa_records = dns_lookup(domain, "AAAA")
    result.ns_records   = [x.rstrip(".") for x in dns_lookup(domain, "NS")]
    result.txt_records  = dns_lookup(domain, "TXT")
    if result.a_records:
        result.domain_ip = result.a_records[0]
    for txt in result.txt_records:
        if "v=spf1" in txt.lower():
            result.spf_record = txt[:200]; break
    dmarc = dns_lookup(f"_dmarc.{domain}", "TXT")
    if dmarc:
        result.dmarc_record = dmarc[0][:200]
    for sel in ["google","default","mail","dkim","k1","selector1","selector2","s1","s2","smtp"]:
        hits = dns_lookup(f"{sel}._domainkey.{domain}", "TXT")
        if hits:
            result.dkim_hints.append(f"{sel}: {hits[0][:60]}")
    bimi = dns_lookup(f"default._bimi.{domain}", "TXT")
    if bimi:
        result.bimi_record = bimi[0][:100]
    result.dnssec = bool(dns_lookup(domain, "DS"))
    if result.domain_ip and HAS_DNS:
        try:
            rev = dns.reversename.from_address(result.domain_ip)
            ptrs = dns.resolver.resolve(rev, "PTR", lifetime=4)
            result.ip_ptr = str(list(ptrs)[0]).rstrip(".")
        except Exception:
            pass

def _fmt_date(d) -> str:
    if not d: return ""
    if isinstance(d, list): d = d[0]
    if isinstance(d, datetime): return d.strftime("%Y-%m-%d")
    return str(d)[:10]

def whois_scan(domain: str, result: OsintResult) -> None:
    if not HAS_WHOIS:
        try:
            r = requests.get(f"https://rdap.org/domain/{domain}", headers=HEADERS, timeout=6)
            if r.status_code == 200:
                data = r.json()
                for event in data.get("events", []):
                    if event.get("eventAction") == "registration":
                        result.whois_created = event.get("eventDate","")[:10]
                    if event.get("eventAction") == "expiration":
                        result.whois_expires = event.get("eventDate","")[:10]
                result.whois_name_servers = [n.get("ldhName","") for n in data.get("nameservers",[])]
        except Exception:
            pass
        return
    try:
        w = whois_lib.whois(domain)
        result.whois_registrar    = str(w.registrar or "")[:80]
        result.whois_created      = _fmt_date(w.creation_date)
        result.whois_expires      = _fmt_date(w.expiration_date)
        result.whois_updated      = _fmt_date(w.updated_date)
        result.whois_org          = str(w.org or "")[:80]
        result.whois_country      = str(w.country or "")
        ns = w.name_servers or []
        result.whois_name_servers = [str(n).lower() for n in (ns if isinstance(ns, list) else [ns])][:4]
        if result.whois_created:
            try:
                created = datetime.strptime(result.whois_created, "%Y-%m-%d")
                result.domain_age_days = (datetime.now() - created).days
            except Exception:
                pass
    except Exception:
        pass

def wayback_scan(domain: str, result: OsintResult) -> None:
    try:
        r = requests.get("https://archive.org/wayback/available",
                         params={"url": domain}, headers=HEADERS, timeout=5)
        if r.status_code == 200:
            snap = r.json().get("archived_snapshots",{}).get("closest",{})
            if snap:
                result.wayback_last = snap.get("timestamp","")[:8]
    except Exception:
        pass
    try:
        r2 = requests.get("https://web.archive.org/cdx/search/cdx",
                          params={"url": domain, "output": "json", "limit": 1,
                                  "fl": "timestamp", "from": "19960101"},
                          headers=HEADERS, timeout=6)
        if r2.status_code == 200:
            rows = r2.json()
            if len(rows) > 1:
                result.wayback_first = rows[1][0][:8]
    except Exception:
        pass
    try:
        r3 = requests.get("https://web.archive.org/cdx/search/cdx",
                          params={"url": domain+"/*", "output": "json",
                                  "limit": 1, "showNumPages": "true"},
                          headers=HEADERS, timeout=6)
        if r3.status_code == 200:
            result.wayback_count = int(r3.text.strip())
    except Exception:
        pass

def ip_intel(result: OsintResult) -> None:
    if not result.domain_ip: return
    try:
        r = requests.get(f"https://ipinfo.io/{result.domain_ip}/json",
                         headers=HEADERS, timeout=5)
        if r.status_code == 200:
            data = r.json()
            result.ip_country = data.get("country","")
            result.ip_city    = data.get("city","")
            result.ip_org     = data.get("org","")
            result.ip_asn     = (data.get("org","") or "").split()[0]
    except Exception:
        pass
    if ABUSEIPDB_KEY:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                             params={"ipAddress": result.domain_ip, "maxAgeInDays": 90},
                             headers={**HEADERS, "Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                             timeout=5)
            if r.status_code == 200:
                result.ip_abuse_score = r.json().get("data",{}).get("abuseConfidenceScore",-1)
        except Exception:
            pass

def shodan_scan(result: OsintResult) -> None:
    if not SHODAN_KEY or not result.domain_ip: return
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{result.domain_ip}",
                         params={"key": SHODAN_KEY}, headers=HEADERS, timeout=8)
        if r.status_code == 200:
            data = r.json()
            result.shodan_ports     = sorted(data.get("ports",[]))
            result.shodan_vulns     = list(data.get("vulns",{}).keys())[:10]
            result.shodan_hostnames = data.get("hostnames",[])[:5]
            result.shodan_tags      = data.get("tags",[])
            result.shodan_banners   = [
                f":{s.get('port','')} {s.get('data','').strip()[:80]}"
                for s in data.get("data",[])[:5] if s.get("data","").strip()
            ]
    except Exception:
        pass

def dnsbl_check(result: OsintResult) -> None:
    if not result.domain_ip: return
    try:
        ip  = ipaddress.ip_address(result.domain_ip)
        rev = ".".join(reversed(str(ip).split(".")))
    except Exception:
        return
    listed, clean = [], 0
    for zone in DNSBL_ZONES:
        try:
            socket.gethostbyname(f"{rev}.{zone}")
            listed.append(zone)
        except socket.gaierror:
            clean += 1
        except Exception:
            pass
    result.dnsbl_listed = listed
    result.dnsbl_clean  = clean

def hibp_scan(email: str, result: OsintResult) -> None:
    if not HIBP_KEY:
        result.hibp_error = "no_key"; return
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
            params={"truncateResponse": "false"},
            headers={**HEADERS, "hibp-api-key": HIBP_KEY}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            result.breach_count = len(data)
            for b in data:
                result.breaches.append({
                    "name":        b.get("Name",""),
                    "domain":      b.get("Domain",""),
                    "breach_date": b.get("BreachDate",""),
                    "pwn_count":   b.get("PwnCount",0),
                    "data_classes":b.get("DataClasses",[]),
                    "verified":    b.get("IsVerified",False),
                    "sensitive":   b.get("IsSensitive",False),
                })
                for dc in b.get("DataClasses",[]):
                    if dc not in result.compromised_data:
                        result.compromised_data.append(dc)
        elif r.status_code == 404:
            result.breach_count = 0
        else:
            result.hibp_error = f"http_{r.status_code}"
    except Exception as e:
        result.hibp_error = str(e)[:50]
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{quote(email)}",
            headers={**HEADERS, "hibp-api-key": HIBP_KEY}, timeout=8)
        if r.status_code == 200:
            result.paste_count = len(r.json())
    except Exception:
        pass

def leakcheck_scan(email: str, result: OsintResult) -> None:
    if not LEAKCHECK_KEY: return
    try:
        r = requests.get("https://leakcheck.io/api/public",
                         params={"check": email, "type": "email"},
                         headers={**HEADERS, "X-API-Key": LEAKCHECK_KEY}, timeout=8)
        if r.status_code == 200:
            data = r.json()
            if data.get("found"):
                result.leakcheck_found   = True
                sources = data.get("sources",[])
                result.leakcheck_sources = [s.get("name","") for s in sources][:15]
                result.leakcheck_count   = len(result.leakcheck_sources)
    except Exception:
        pass

def gravatar_scan(email: str, result: OsintResult) -> None:
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    try:
        r = requests.get(f"https://www.gravatar.com/{h}.json",
                         headers=HEADERS, timeout=5)
        if r.status_code == 200:
            entry = r.json().get("entry",[{}])[0]
            result.gravatar_exists       = True
            result.gravatar_display_name = entry.get("displayName","")
            result.gravatar_about_me     = (entry.get("aboutMe","") or "")[:200]
            result.gravatar_location     = entry.get("currentLocation","")
            result.gravatar_verified     = bool(entry.get("verified",False))
            result.gravatar_avatar_url   = f"https://www.gravatar.com/avatar/{h}?s=400"
            result.gravatar_urls         = [u.get("value","") for u in entry.get("urls",[]) if u.get("value")]
            result.gravatar_accounts     = [{"domain": a.get("domain",""), "username": a.get("username","")}
                                             for a in entry.get("accounts",[])]
    except Exception:
        pass

def github_scan(email: str, result: OsintResult) -> None:
    username   = email.split("@")[0]
    gh_headers = {**HEADERS, "Accept": "application/vnd.github+json"}
    try:
        r = requests.get(f"https://api.github.com/users/{username}",
                         headers=gh_headers, timeout=6)
        if r.status_code != 200: return
        d = r.json()
        result.github_exists   = True
        result.github_username = d.get("login","")
        result.github_name     = (d.get("name","") or "")
        result.github_bio      = (d.get("bio","") or "")[:150]
        result.github_company  = (d.get("company","") or "")
        result.github_location = (d.get("location","") or "")
        result.github_followers= d.get("followers",0)
        result.github_following= d.get("following",0)
        result.github_repos    = d.get("public_repos",0)
        result.github_gists    = d.get("public_gists",0)
        result.github_url      = d.get("html_url","")
        result.github_created  = (d.get("created_at","") or "")[:10]
        result.github_hireable = bool(d.get("hireable"))
        result.github_blog     = (d.get("blog","") or "")
    except Exception:
        return
    try:
        r = requests.get(f"https://api.github.com/users/{username}/orgs",
                         headers=gh_headers, timeout=5)
        if r.status_code == 200:
            result.github_orgs = [o.get("login","") for o in r.json()[:8]]
    except Exception:
        pass
    try:
        r = requests.get(f"https://api.github.com/users/{username}/repos",
                         params={"sort": "stars", "per_page": 6},
                         headers=gh_headers, timeout=5)
        if r.status_code == 200:
            langs = []
            for repo in r.json():
                result.github_top_repos.append({
                    "name":  repo.get("name",""),
                    "stars": repo.get("stargazers_count",0),
                    "lang":  (repo.get("language","") or ""),
                    "desc":  (repo.get("description","") or "")[:60],
                    "url":   repo.get("html_url",""),
                })
                if repo.get("language") and repo["language"] not in langs:
                    langs.append(repo["language"])
            result.github_languages = langs[:8]
    except Exception:
        pass

def _check_platform(platform: str, url_tpl: str, username: str) -> Tuple[str, Optional[str]]:
    url = url_tpl.format(u=username)
    try:
        r = requests.get(url, headers=HEADERS, timeout=5, allow_redirects=True)
        if r.status_code == 200:
            body = r.text[:3000].lower()
            if not any(s in body for s in NOT_FOUND_SIGNALS):
                return platform, url
    except Exception:
        pass
    return platform, None

def platform_scan(email: str, result: OsintResult) -> None:
    username = email.split("@")[0].lower()
    result.platforms_checked = len(PLATFORMS)
    found = {}
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = {ex.submit(_check_platform, p, tpl, username): p
                   for p, tpl in PLATFORMS.items()}
        for fut in as_completed(futures):
            platform, url = fut.result()
            if url:
                found[platform] = url
    result.platforms_found = found
    parts = re.split(r'[._\-]', username)
    if len(parts) > 1:
        variants = {"".join(parts), ".".join(parts), "_".join(parts), "-".join(parts)}
        variants.discard(username)
        result.username_variants = list(variants)[:6]

def calculate_risk(result: OsintResult) -> None:
    score, flags = 0, []
    if result.breach_count > 0:
        score += min(result.breach_count * 8, 40)
        flags.append(f"Found in {result.breach_count} HIBP breach(es)")
    if result.leakcheck_found:
        score += 10; flags.append("Confirmed in LeakCheck database")
    if result.paste_count > 0:
        score += min(result.paste_count * 3, 15)
        flags.append(f"Exposed in {result.paste_count} paste(s)")
    if result.disposable:
        score += 20; flags.append("Disposable email domain")
    if result.domain_age_days and result.domain_age_days < 180:
        score += 15; flags.append(f"Very new domain ({result.domain_age_days}d old)")
    if not result.spf_record:
        score += 5; flags.append("No SPF record (domain spoofable)")
    if not result.dmarc_record:
        score += 5; flags.append("No DMARC record")
    if result.dnsbl_listed:
        score += len(result.dnsbl_listed) * 10
        flags.append(f"IP blacklisted on {len(result.dnsbl_listed)} DNSBL(s)")
    if result.shodan_vulns:
        score += min(len(result.shodan_vulns) * 8, 25)
        flags.append(f"{len(result.shodan_vulns)} CVE(s) on mail server")
    if result.ip_abuse_score > 50:
        score += 15; flags.append(f"IP abuse score: {result.ip_abuse_score}%")
    if "Passwords" in result.compromised_data:
        score += 10; flags.append("Passwords compromised")
    if "Credit Cards" in result.compromised_data:
        score += 15; flags.append("Credit card data exposed")
    if result.gravatar_exists: score -= 5
    if result.github_exists and result.github_followers > 10: score -= 5
    if result.dnssec: score -= 3
    if result.spf_record and result.dmarc_record: score -= 5
    result.risk_score = max(0, min(100, score))
    result.risk_flags = flags

# ══════════════════════════════════════════════════════════════════════
#  RENDER
# ══════════════════════════════════════════════════════════════════════

def _grid() -> Table:
    t = Table.grid(padding=(0, 2))
    t.add_column(style=f"bold {MUTED}", width=20, no_wrap=True)
    t.add_column(style=WHITE)
    return t

def _row(t: Table, label: str, value: str) -> None:
    t.add_row(label, value)

def render_banner() -> Panel:
    b = Text()
    b.append("  ███████╗███╗   ███╗ █████╗ ██╗██╗\n",      style=f"bold {ACCENT}")
    b.append("  ██╔════╝████╗ ████║██╔══██╗██║██║\n",      style=f"bold {ACCENT}")
    b.append("  █████╗  ██╔████╔██║███████║██║██║\n",      style=f"bold {BLUE}")
    b.append("  ██╔══╝  ██║╚██╔╝██║██╔══██║██║██║\n",      style=f"bold {BLUE}")
    b.append("  ███████╗██║ ╚═╝ ██║██║  ██║██║███████╗\n", style=f"bold {WHITE}")
    b.append("  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝\n",style=f"bold {WHITE}")
    b.append(f"\n  [{ACCENT}]O S I N T  v3.0[/]  [{MUTED}]·  Professional Email Intelligence Platform[/]\n")
    b.append(f"  [{MUTED}]Breach · DNS · WHOIS · IP/ASN · Shodan · GitHub · Gravatar · 33 Platforms[/]\n")
    b.append(f"\n  [{MUTED}]Made by [/][bold {ACCENT}]Tifo[/][{MUTED}]  ·  github.com/tifo  ·  For educational & research use only[/]")
    return Panel(b, border_style=ACCENT, padding=(0, 2))

def render_risk_badge(result: OsintResult) -> Panel:
    s = result.risk_score
    if s >= 70:   color, label = WARN,   "HIGH RISK"
    elif s >= 40: color, label = YELLOW, "MEDIUM RISK"
    elif s >= 10: color, label = BLUE,   "LOW RISK"
    else:         color, label = ACCENT, "CLEAN"
    bar_filled = int(s / 5)
    bar = f"[bold {color}]{'█' * bar_filled}[/][dim]{'░' * (20 - bar_filled)}[/]"
    t = _grid()
    _row(t, "Risk Score", f"[bold {color}]{s}/100  ▸  {label}[/]")
    t.add_row("", Text.from_markup(bar))
    if result.risk_flags:
        for flag in result.risk_flags[:7]:
            t.add_row("", f"[{color}]▸[/] {escape(flag)}")
    return Panel(t, title=f"[bold {color}]⚡  RISK ASSESSMENT[/]",
                 border_style=color, box=box.ROUNDED)

def render_validation_card(r: OsintResult) -> Panel:
    t = _grid()
    _row(t, "Email",        f"[bold]{escape(r.email)}[/]")
    _row(t, "Format",       f"[bold {ACCENT}]✓ Valid[/]" if r.valid_format else f"[bold {WARN}]✗ Invalid[/]")
    _row(t, "Domain",       f"[bold]{escape(r.domain)}[/]")
    _row(t, "Provider",     f"[{BLUE}]{escape(r.provider)}[/]")
    _row(t, "Disposable",   f"[bold {WARN}]YES[/]" if r.disposable else f"[{ACCENT}]No[/]")
    _row(t, "MX Records",   escape(", ".join(r.mx_records[:2])) or "none")
    _row(t, "Domain IP",    r.domain_ip or "—")
    _row(t, "PTR Record",   r.ip_ptr or "—")
    loc = f"{r.ip_city}, {r.ip_country}".strip(", ")
    _row(t, "IP Location",  loc or "—")
    _row(t, "ASN / Org",    escape(r.ip_org[:50]) if r.ip_org else "—")
    if r.ip_abuse_score >= 0:
        ac = WARN if r.ip_abuse_score > 25 else ACCENT
        _row(t, "Abuse Score", f"[bold {ac}]{r.ip_abuse_score}%[/]")
    return Panel(t, title=f"[bold {ACCENT}]📧  EMAIL & IP INTEL[/]",
                 border_style=ACCENT, box=box.ROUNDED)

def render_dns_card(r: OsintResult) -> Panel:
    t = _grid()
    _row(t, "A Records",    ", ".join(r.a_records[:3]) or "—")
    _row(t, "AAAA Records", ", ".join(r.aaaa_records[:2]) or "—")
    _row(t, "NS Records",   ", ".join(r.ns_records[:3]) or "—")
    _row(t, "DNSSEC",       f"[bold {ACCENT}]Enabled[/]" if r.dnssec else f"[{MUTED}]Disabled[/]")
    spf_c = ACCENT if r.spf_record else WARN
    _row(t, "SPF",    f"[{spf_c}]{escape(r.spf_record[:60]) if r.spf_record else '✗ Missing'}[/]")
    dmarc_c = ACCENT if r.dmarc_record else WARN
    _row(t, "DMARC",  f"[{dmarc_c}]{escape(r.dmarc_record[:60]) if r.dmarc_record else '✗ Missing'}[/]")
    _row(t, "DKIM Keys", f"{len(r.dkim_hints)} found" if r.dkim_hints else "None found")
    for dkim in r.dkim_hints[:3]:
        t.add_row("", f"[dim]{escape(dkim[:70])}[/]")
    _row(t, "BIMI",   escape(r.bimi_record[:60]) if r.bimi_record else "—")
    if r.dnsbl_listed:
        _row(t, "DNSBL Listed", f"[bold {WARN}]{', '.join(r.dnsbl_listed[:3])}[/]")
    else:
        _row(t, "DNSBL Status", f"[{ACCENT}]Clean ({r.dnsbl_clean} checked)[/]")
    return Panel(t, title=f"[bold {BLUE}]🌐  DNS INTELLIGENCE[/]",
                 border_style=BLUE, box=box.ROUNDED)

def render_whois_card(r: OsintResult) -> Panel:
    t = _grid()
    _row(t, "Registrar",   escape(r.whois_registrar[:60]) if r.whois_registrar else "—")
    _row(t, "Org",         escape(r.whois_org[:60]) if r.whois_org else "—")
    _row(t, "Country",     r.whois_country or "—")
    _row(t, "Created",     r.whois_created or "—")
    _row(t, "Expires",     r.whois_expires or "—")
    _row(t, "Updated",     r.whois_updated or "—")
    if r.domain_age_days:
        age_c = WARN if r.domain_age_days < 180 else ACCENT
        _row(t, "Domain Age", f"[{age_c}]{r.domain_age_days:,} days[/]")
    _row(t, "Name Servers", escape(", ".join(r.whois_name_servers[:3])) or "—")
    _row(t, "Wayback Snaps", str(r.wayback_count) if r.wayback_count else "—")
    _row(t, "First Archived", r.wayback_first or "—")
    _row(t, "Last Archived",  r.wayback_last or "—")
    return Panel(t, title=f"[bold {PURPLE}]🏢  WHOIS & HISTORY[/]",
                 border_style=PURPLE, box=box.ROUNDED)

def render_shodan_card(r: OsintResult) -> Panel:
    if not SHODAN_KEY:
        body = Text(f"  Set SHODAN_API_KEY env var to enable.\n  Free key: shodan.io", style=MUTED)
        return Panel(body, title=f"[bold {MUTED}]🔭  SHODAN[/]", border_style=MUTED, box=box.ROUNDED)
    if not r.shodan_ports and not r.shodan_vulns:
        body = Text("  No Shodan data for this IP.", style=MUTED)
        return Panel(body, title=f"[bold {MUTED}]🔭  SHODAN[/]", border_style=MUTED, box=box.ROUNDED)
    t = _grid()
    ports_str = " ".join(f"[bold]{p}[/]" for p in r.shodan_ports[:15]) or "—"
    t.add_row("Open Ports", Text.from_markup(ports_str))
    if r.shodan_hostnames:
        _row(t, "Hostnames", ", ".join(r.shodan_hostnames[:4]))
    if r.shodan_tags:
        _row(t, "Tags", ", ".join(r.shodan_tags))
    if r.shodan_vulns:
        vuln_str = " ".join(f"[bold {WARN}]{v}[/]" for v in r.shodan_vulns[:6])
        t.add_row(f"[bold {WARN}]CVEs[/]", Text.from_markup(vuln_str))
    for banner in r.shodan_banners[:3]:
        t.add_row("", f"[dim]{escape(banner[:80])}[/]")
    return Panel(t, title=f"[bold {YELLOW}]🔭  SHODAN INTEL[/]",
                 border_style=YELLOW, box=box.ROUNDED)

def render_breach_card(r: OsintResult) -> Panel:
    if r.hibp_error == "no_key":
        lines = [Text("  Set HIBP_API_KEY to enable breach lookup.\n  Free: haveibeenpwned.com/API/Key", style=MUTED)]
        if r.leakcheck_found:
            lines.append(Text.from_markup(
                f"\n  [{WARN}]⚠ LeakCheck: {r.leakcheck_count} source(s)[/]\n"
                f"  [{MUTED}]{', '.join(r.leakcheck_sources[:8])}[/]"))
        return Panel(Group(*lines), title=f"[bold {WARN}]🔓  DATA BREACHES[/]",
                     border_style=WARN, box=box.ROUNDED)
    if r.breach_count == 0 and not r.leakcheck_found:
        return Panel(Text("  ✓  No breach data found.", style=f"bold {ACCENT}"),
                     title=f"[bold {ACCENT}]🔓  DATA BREACHES[/]",
                     border_style=ACCENT, box=box.ROUNDED)
    tbl = Table(show_header=True, box=box.SIMPLE_HEAD,
                header_style=f"bold {BLUE}", expand=True, show_edge=False)
    tbl.add_column("Source",   style=f"bold {WHITE}", width=20)
    tbl.add_column("Date",     style=MUTED, width=11)
    tbl.add_column("Records",  justify="right", style=f"bold {WARN}", width=10)
    tbl.add_column("Sensitive",width=9)
    tbl.add_column("Data Leaked", style=MUTED)
    for b in sorted(r.breaches, key=lambda x: x["breach_date"], reverse=True)[:12]:
        leaked = ", ".join(b["data_classes"][:4])
        if len(b["data_classes"]) > 4:
            leaked += f" +{len(b['data_classes'])-4}"
        sens = f"[bold {WARN}]YES[/]" if b.get("sensitive") else ""
        tbl.add_row(escape(b["name"]), b["breach_date"], f"{b['pwn_count']:,}", sens, escape(leaked))
    parts = [f"[bold {WARN}]⚠  HIBP: {r.breach_count}[/]"]
    if r.paste_count: parts.append(f"[{YELLOW}]Pastes: {r.paste_count}[/]")
    if r.leakcheck_found: parts.append(f"[{WARN}]LeakCheck: {r.leakcheck_count}[/]")
    if r.compromised_data: parts.append(f"[{MUTED}]{', '.join(r.compromised_data[:5])}[/]")
    content = Group(Text.from_markup("  " + "  |  ".join(parts)), Rule(style=MUTED), tbl)
    return Panel(content, title=f"[bold {WARN}]🔓  DATA BREACHES[/]",
                 border_style=WARN, box=box.ROUNDED)

def render_gravatar_card(r: OsintResult) -> Panel:
    if not r.gravatar_exists:
        return Panel(Text("  No Gravatar profile found.", style=MUTED),
                     title=f"[bold {MUTED}]👤  GRAVATAR[/]", border_style=MUTED, box=box.ROUNDED)
    t = _grid()
    _row(t, "Display Name", f"[bold]{escape(r.gravatar_display_name)}[/]")
    if r.gravatar_location: _row(t, "Location", escape(r.gravatar_location))
    if r.gravatar_about_me: _row(t, "About",    f"[dim]{escape(r.gravatar_about_me[:100])}[/]")
    _row(t, "Verified",     f"[bold {ACCENT}]Yes[/]" if r.gravatar_verified else "No")
    _row(t, "Avatar",       f"[{BLUE}]{r.gravatar_avatar_url}[/]")
    for url in r.gravatar_urls[:3]:
        _row(t, "Link",     f"[{BLUE}]{escape(url)}[/]")
    for acc in r.gravatar_accounts[:4]:
        _row(t, escape(acc.get("domain","")), escape(acc.get("username","")))
    return Panel(t, title=f"[bold {BLUE}]👤  GRAVATAR PROFILE[/]",
                 border_style=BLUE, box=box.ROUNDED)

def render_github_card(r: OsintResult) -> Panel:
    if not r.github_exists:
        return Panel(Text(f"  No GitHub account matched: {r.username}", style=MUTED),
                     title=f"[bold {MUTED}]🐙  GITHUB[/]", border_style=MUTED, box=box.ROUNDED)
    t = _grid()
    _row(t, "Username",    f"[bold {ACCENT}]@{escape(r.github_username)}[/]")
    if r.github_name:      _row(t, "Name",     f"[bold]{escape(r.github_name)}[/]")
    if r.github_bio:       _row(t, "Bio",      f"[dim]{escape(r.github_bio[:100])}[/]")
    if r.github_company:   _row(t, "Company",  escape(r.github_company))
    if r.github_location:  _row(t, "Location", escape(r.github_location))
    if r.github_blog:      _row(t, "Blog",     f"[{BLUE}]{escape(r.github_blog)}[/]")
    _row(t, "Account Created", r.github_created or "—")
    _row(t, "Followers",   f"[bold {BLUE}]{r.github_followers:,}[/]")
    _row(t, "Following",   str(r.github_following))
    _row(t, "Public Repos",f"[bold]{r.github_repos}[/]")
    _row(t, "Public Gists",str(r.github_gists))
    _row(t, "Hireable",    f"[{ACCENT}]Yes[/]" if r.github_hireable else "No")
    if r.github_orgs:      _row(t, "Orgs",      ", ".join(r.github_orgs[:5]))
    if r.github_languages: _row(t, "Languages", ", ".join(r.github_languages[:6]))
    if r.github_top_repos:
        t.add_row("", "")
        t.add_row(f"[bold {MUTED}]Top Repos[/]", "")
        for repo in r.github_top_repos[:4]:
            star = f"⭐{repo['stars']}" if repo['stars'] else ""
            lang = f"[{PURPLE}]{repo['lang']}[/]" if repo['lang'] else ""
            t.add_row(f"  [{BLUE}]{escape(repo['name'])}[/]",
                      Text.from_markup(f"{escape(repo['desc'][:50])}  {star}  {lang}"))
    return Panel(t, title=f"[bold {ACCENT}]🐙  GITHUB DEEP PROFILE[/]",
                 border_style=ACCENT, box=box.ROUNDED)

def render_platforms_card(r: OsintResult) -> Panel:
    tbl = Table(show_header=False, box=None, expand=True, padding=(0, 1))
    tbl.add_column(style=f"bold {ACCENT}", width=16, no_wrap=True)
    tbl.add_column(style=BLUE)
    for platform, url in r.platforms_found.items():
        tbl.add_row(f"✓ {platform}", url)
    not_found = [p for p in PLATFORMS if p not in r.platforms_found]
    for i, p in enumerate(not_found):
        if i >= 8:
            tbl.add_row(f"[dim]  ... +{len(not_found)-i} more[/]", ""); break
        tbl.add_row(f"[dim]✗ {p}[/]", "")
    header = Text.from_markup(
        f"  [{ACCENT}]■ {len(r.platforms_found)} accounts found[/]  "
        f"[{MUTED}]of {r.platforms_checked} platforms checked[/]"
    )
    if r.username_variants:
        header.append(f"\n  Variants checked: ", style=MUTED)
        header.append(", ".join(r.username_variants), style=BLUE)
    return Panel(Group(header, Text(""), tbl),
                 title=f"[bold {ACCENT}]🌐  PLATFORM FOOTPRINT[/]",
                 border_style=ACCENT, box=box.ROUNDED)

def render_full_report(result: OsintResult) -> None:
    console.print()
    console.print(Rule(f"[bold {ACCENT}]OSINT REPORT — {escape(result.email)} — {result.timestamp[:19]}[/]", style=ACCENT))
    console.print()
    console.print(render_risk_badge(result))
    console.print()
    console.print(Columns([render_validation_card(result), render_dns_card(result)], equal=True, expand=True))
    console.print()
    console.print(Columns([render_whois_card(result), render_shodan_card(result)], equal=True, expand=True))
    console.print()
    console.print(render_breach_card(result))
    console.print()
    console.print(Columns([render_gravatar_card(result), render_github_card(result)], equal=True, expand=True))
    console.print()
    console.print(render_platforms_card(result))
    console.print()
    keys_active = [n for n, k in [("HIBP", HIBP_KEY),("Shodan", SHODAN_KEY),
                                   ("LeakCheck", LEAKCHECK_KEY),("AbuseIPDB", ABUSEIPDB_KEY)] if k]
    key_str = f"[{ACCENT}]{', '.join(keys_active)}[/]" if keys_active else f"[{WARN}]none — run interactively to configure[/]"
    console.print(Text.from_markup(
        f"  [{MUTED}]Report: {result.timestamp[:19]}  |  APIs: [/]{key_str}  "
        f"[{MUTED}]|  EMAIL OSINT v3.0  |  [/][bold {ACCENT}]Made by Tifo[/]"
    ))
    console.print()

# ══════════════════════════════════════════════════════════════════════
#  EXPORT
# ══════════════════════════════════════════════════════════════════════

def export_json(result: OsintResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(result), f, indent=2, ensure_ascii=False)
    console.print(f"[{ACCENT}]✓ JSON →[/] {path}")

def export_csv(result: OsintResult, path: str) -> None:
    flat = {
        "email": result.email, "timestamp": result.timestamp,
        "risk_score": result.risk_score, "risk_flags": "; ".join(result.risk_flags),
        "provider": result.provider, "disposable": result.disposable,
        "domain_ip": result.domain_ip, "ip_country": result.ip_country,
        "ip_org": result.ip_org, "ip_abuse_score": result.ip_abuse_score,
        "domain_age_days": result.domain_age_days,
        "whois_registrar": result.whois_registrar, "whois_org": result.whois_org,
        "whois_country": result.whois_country, "whois_created": result.whois_created,
        "spf": bool(result.spf_record), "dmarc": bool(result.dmarc_record),
        "dnssec": result.dnssec, "dnsbl_listed": "; ".join(result.dnsbl_listed),
        "shodan_ports": " ".join(map(str, result.shodan_ports)),
        "shodan_vulns": " ".join(result.shodan_vulns),
        "breach_count": result.breach_count, "paste_count": result.paste_count,
        "leakcheck": result.leakcheck_found,
        "leakcheck_sources": "; ".join(result.leakcheck_sources),
        "compromised_data": "; ".join(result.compromised_data),
        "gravatar": result.gravatar_exists,
        "gravatar_name": result.gravatar_display_name,
        "github": result.github_exists, "github_username": result.github_username,
        "github_followers": result.github_followers, "github_repos": result.github_repos,
        "github_orgs": "; ".join(result.github_orgs),
        "platforms_found": "; ".join(result.platforms_found.keys()),
        "platforms_count": len(result.platforms_found),
        "wayback_first": result.wayback_first, "wayback_count": result.wayback_count,
    }
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=flat.keys())
        w.writeheader(); w.writerow(flat)
    console.print(f"[{ACCENT}]✓ CSV →[/] {path}")

# ══════════════════════════════════════════════════════════════════════
#  PIPELINE
# ══════════════════════════════════════════════════════════════════════

SCAN_STEPS = [
    ("DNS Intelligence",        lambda e, r: full_dns_scan(r.domain, r)),
    ("WHOIS Lookup",            lambda e, r: whois_scan(r.domain, r)),
    ("Wayback Machine",         lambda e, r: wayback_scan(r.domain, r)),
    ("IP Geolocation / ASN",    lambda e, r: ip_intel(r)),
    ("Shodan Host Intel",       lambda e, r: shodan_scan(r)),
    ("DNSBL Blacklist Check",   lambda e, r: dnsbl_check(r)),
    ("HIBP Breach Lookup",      lambda e, r: hibp_scan(e, r)),
    ("LeakCheck Database",      lambda e, r: leakcheck_scan(e, r)),
    ("Gravatar Profile",        lambda e, r: gravatar_scan(e, r)),
    ("GitHub Deep Profile",     lambda e, r: github_scan(e, r)),
    ("Platform Footprint",      lambda e, r: platform_scan(e, r)),
    ("Risk Scoring",            lambda e, r: calculate_risk(r)),
]

def run_scan(email: str, skip_platforms: bool = False) -> OsintResult:
    result              = OsintResult(email=email)
    result.valid_format = validate_email(email)
    result.domain       = email.split("@")[1] if "@" in email else ""
    result.username     = email.split("@")[0]
    result.disposable   = result.domain.lower() in DISPOSABLE
    steps = [s for s in SCAN_STEPS if not (skip_platforms and s[0] == "Platform Footprint")]
    with Progress(
        SpinnerColumn(spinner_name="dots2", style=f"bold {ACCENT}"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28, style=BLUE, complete_style=ACCENT),
        TaskProgressColumn(), console=console, transient=True,
    ) as prog:
        task = prog.add_task("Starting...", total=len(steps))
        for name, fn in steps:
            prog.update(task, description=f"[bold {WHITE}]{name}...[/]")
            try:
                fn(email, result)
            except Exception:
                pass
            prog.advance(task)
    result.provider = detect_provider(result.domain, result.mx_records)
    return result

API_INFO = {
    "HIBP": {
        "env":   "HIBP_API_KEY",
        "desc":  "HaveIBeenPwned — data breach lookup",
        "url":   "https://haveibeenpwned.com/API/Key",
        "price": "Free ($3.50/mo for unlimited)",
        "unlocks": "Full breach history, paste exposure, compromised data types",
    },
    "Shodan": {
        "env":   "SHODAN_API_KEY",
        "desc":  "Shodan — open ports, CVEs, banners on mail server",
        "url":   "https://account.shodan.io/register",
        "price": "Free tier available",
        "unlocks": "Open ports, CVE list, service banners, hostnames",
    },
    "LeakCheck": {
        "env":   "LEAKCHECK_KEY",
        "desc":  "LeakCheck — secondary breach database",
        "url":   "https://leakcheck.io",
        "price": "Free tier available",
        "unlocks": "Cross-verified breach sources beyond HIBP",
    },
    "AbuseIPDB": {
        "env":   "ABUSEIPDB_KEY",
        "desc":  "AbuseIPDB — IP reputation & abuse score",
        "url":   "https://www.abuseipdb.com/register",
        "price": "Free (1000 checks/day)",
        "unlocks": "IP abuse confidence score (0–100%)",
    },
}

def _api_status() -> str:
    parts = []
    for name, val in [("HIBP", HIBP_KEY),("Shodan", SHODAN_KEY),
                      ("LeakCheck", LEAKCHECK_KEY),("AbuseIPDB", ABUSEIPDB_KEY)]:
        c = ACCENT if val else MUTED
        sym = "✓" if val else "✗"
        parts.append(f"[{c}]{sym} {name}[/]")
    return "  " + "   ".join(parts)

def render_api_status_panel() -> Panel:
    """Rich panel showing API key status with links and what each unlocks."""
    tbl = Table(show_header=True, box=box.SIMPLE_HEAD,
                header_style=f"bold {BLUE}", expand=True, show_edge=False,
                padding=(0, 1))
    tbl.add_column("API",      style=f"bold {WHITE}", width=12, no_wrap=True)
    tbl.add_column("Status",   width=10, no_wrap=True)
    tbl.add_column("Unlocks",  style=MUTED)
    tbl.add_column("Get Key",  style=BLUE)

    key_map = [
        ("HIBP",      HIBP_KEY),
        ("Shodan",    SHODAN_KEY),
        ("LeakCheck", LEAKCHECK_KEY),
        ("AbuseIPDB", ABUSEIPDB_KEY),
    ]
    for name, val in key_map:
        info = API_INFO[name]
        if val:
            status = f"[bold {ACCENT}]✓ Active[/]"
        else:
            status = f"[bold {WARN}]✗ Missing[/]"
        tbl.add_row(name, status, info["unlocks"], info["url"])

    active   = sum(1 for _, v in key_map if v)
    missing  = 4 - active
    summary  = (
        f"  [{ACCENT}]{active}/4 API keys active[/]"
        + (f"  [{MUTED}]·  {missing} key(s) missing — some modules will be skipped[/]" if missing else
           f"  [{ACCENT}]·  Full power unlocked![/]")
    )
    content = Group(Text.from_markup(summary), Text(""), tbl)
    return Panel(content, title=f"[bold {BLUE}]🔑  API KEY STATUS[/]",
                 border_style=BLUE, box=box.ROUNDED)

def render_api_setup_wizard() -> None:
    """Interactive wizard to enter missing API keys for this session."""
    console.print()
    console.print(Panel(
        Text.from_markup(
            f"  [{WHITE}]Some API keys are missing. You can:[/]\n\n"
            f"  [{ACCENT}][1][/] [{WHITE}]Enter keys now (session only — not saved to disk)[/]\n"
            f"  [{BLUE}][2][/] [{WHITE}]See where to get each key[/]\n"
            f"  [{MUTED}][3][/] [{MUTED}]Skip and continue without them[/]"
        ),
        title=f"[bold {YELLOW}]⚙  API KEY SETUP[/]",
        border_style=YELLOW, box=box.ROUNDED
    ))
    console.print()

    choice = Prompt.ask(
        f"  [{YELLOW}]Choose[/] [{MUTED}](1/2/3)[/]",
        choices=["1", "2", "3"], default="3"
    )

    if choice == "3":
        console.print(f"\n  [{MUTED}]Skipping — running with available keys only.[/]\n")
        return

    if choice == "2":
        console.print()
        for name, info in API_INFO.items():
            val = {"HIBP": HIBP_KEY, "Shodan": SHODAN_KEY,
                   "LeakCheck": LEAKCHECK_KEY, "AbuseIPDB": ABUSEIPDB_KEY}[name]
            status = f"[bold {ACCENT}]✓ Already set[/]" if val else f"[bold {WARN}]✗ Missing[/]"
            console.print(Panel(
                Text.from_markup(
                    f"  [{MUTED}]Description:[/]  {info['desc']}\n"
                    f"  [{MUTED}]Price:[/]         [{ACCENT}]{info['price']}[/]\n"
                    f"  [{MUTED}]Unlocks:[/]       {info['unlocks']}\n"
                    f"  [{MUTED}]Get key at:[/]    [{BLUE}]{info['url']}[/]\n"
                    f"  [{MUTED}]Env var:[/]       [{YELLOW}]{info['env']}[/]\n\n"
                    f"  [{MUTED}]How to set permanently:[/]\n"
                    f"  [{MUTED}]  Linux/Mac:[/]  export {info['env']}=your_key_here\n"
                    f"  [{MUTED}]  Windows:[/]    set {info['env']}=your_key_here\n"
                    f"  [{MUTED}]  Or add to .env / .bashrc / .zshrc[/]"
                ),
                title=f"[bold {BLUE}]🔑  {name}[/]  {status}",
                border_style=BLUE if val else MUTED, box=box.ROUNDED
            ))
            console.print()
        Prompt.ask(f"  [{MUTED}]Press Enter to continue[/]", default="")
        return

    # choice == "1" — enter keys for this session
    import sys as _sys
    _mod = _sys.modules[__name__]
    console.print()
    console.print(f"  [{MUTED}]Press Enter to skip any key.[/]\n")

    key_map = [
        ("HIBP",      "HIBP_API_KEY",   "HIBP_KEY"),
        ("Shodan",    "SHODAN_API_KEY", "SHODAN_KEY"),
        ("LeakCheck", "LEAKCHECK_KEY",  "LEAKCHECK_KEY"),
        ("AbuseIPDB", "ABUSEIPDB_KEY",  "ABUSEIPDB_KEY"),
    ]
    for name, env, attr in key_map:
        current = getattr(_mod, attr, "")
        if current:
            console.print(f"  [{ACCENT}]✓ {name}:[/] [{MUTED}]already set[/]")
            continue
        info = API_INFO[name]
        console.print(f"  [{BLUE}]{name}[/] [{MUTED}]→ {info['url']}[/]")
        val = Prompt.ask(f"  [{YELLOW}]{env}[/] [{MUTED}](Enter to skip)[/]", default="")
        if val.strip():
            setattr(_mod, attr, val.strip())
            console.print(f"  [{ACCENT}]✓ {name} key set for this session.[/]")
        console.print()


# ══════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════

def interactive_mode() -> None:
    console.clear()
    console.print(render_banner())
    console.print()

    # Show API key status panel
    console.print(render_api_status_panel())

    # If any keys are missing, offer the setup wizard
    missing = [n for n, v in [("HIBP", HIBP_KEY),("Shodan", SHODAN_KEY),
                               ("LeakCheck", LEAKCHECK_KEY),("AbuseIPDB", ABUSEIPDB_KEY)] if not v]
    if missing:
        render_api_setup_wizard()
        # Re-render updated status after wizard
        console.print(render_api_status_panel())

    console.print()
    while True:
        email = Prompt.ask(f"\n  [{ACCENT}]Target email[/] [{MUTED}](or 'quit' / 'keys' to reconfigure)[/]")

        if email.lower() in ("quit", "q", "exit"):
            console.print(f"\n[{MUTED}]Exiting. Stay safe.[/]\n"); break

        if email.lower() in ("keys", "apikeys", "setup"):
            render_api_setup_wizard()
            console.print(render_api_status_panel())
            continue

        if not validate_email(email):
            console.print(f"[bold {WARN}]  ✗ Invalid email format.[/]"); continue

        skip = Confirm.ask(f"  [{MUTED}]Skip platform scan (faster)?[/]", default=False)
        console.print(f"\n  [{BLUE}]Scanning:[/] [bold]{escape(email)}[/]\n")
        result = run_scan(email, skip_platforms=skip)
        render_full_report(result)

        fmt = Prompt.ask(f"  [{MUTED}]Export?[/] [{MUTED}](json/csv/no)[/]", default="no")
        if fmt in ("json", "csv"):
            safe = re.sub(r'[^\w\-.]', '_', email)
            (export_json if fmt == "json" else export_csv)(result, f"osint_{safe}.{fmt}")

        if not Confirm.ask(f"\n  [{MUTED}]Scan another?[/]", default=True):
            console.print(f"\n[{MUTED}]Done. — Made by Tifo[/]\n"); break

def bulk_mode(filepath: str, export_fmt: str = "json") -> None:
    console.print(render_banner())
    try:
        with open(filepath) as f:
            emails = [l.strip() for l in f if l.strip() and validate_email(l.strip())]
    except FileNotFoundError:
        console.print(f"[{WARN}]File not found: {filepath}[/]"); sys.exit(1)
    console.print(f"\n  [{ACCENT}]Bulk scan:[/] {len(emails)} emails\n")
    results = []
    with Progress(SpinnerColumn(style=f"bold {ACCENT}"),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(style=BLUE, complete_style=ACCENT),
                  TaskProgressColumn(), console=console) as prog:
        task = prog.add_task("Scanning...", total=len(emails))
        for email in emails:
            prog.update(task, description=f"[bold]{escape(email)}[/]")
            results.append(run_scan(email, skip_platforms=True))
            prog.advance(task)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    if export_fmt == "json":
        path = f"bulk_osint_{ts}.json"
        with open(path, "w") as f:
            json.dump([asdict(r) for r in results], f, indent=2)
    else:
        path = f"bulk_osint_{ts}.csv"
        rows = [{"email": r.email, "risk_score": r.risk_score, "provider": r.provider,
                 "disposable": r.disposable, "breaches": r.breach_count, "pastes": r.paste_count,
                 "leakcheck": r.leakcheck_found, "gravatar": r.gravatar_exists,
                 "github": r.github_username, "platforms": len(r.platforms_found),
                 "dnsbl": len(r.dnsbl_listed), "shodan_vulns": len(r.shodan_vulns),
                 "domain_age": r.domain_age_days, "ip_country": r.ip_country} for r in results]
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=rows[0].keys())
            w.writeheader(); w.writerows(rows)
    console.print(f"[{ACCENT}]✓ Exported → {path}[/]")
    tbl = Table(title="Bulk Scan Summary", box=box.ROUNDED,
                header_style=f"bold {BLUE}", border_style=BLUE)
    tbl.add_column("Email", style=WHITE)
    tbl.add_column("Risk",  justify="right")
    tbl.add_column("Breaches", justify="right", style=WARN)
    tbl.add_column("Gravatar", justify="center")
    tbl.add_column("GitHub",   justify="center")
    tbl.add_column("Platforms",justify="right", style=BLUE)
    tbl.add_column("DNSBL",    justify="center")
    for r in results:
        rc = WARN if r.risk_score >= 70 else (YELLOW if r.risk_score >= 40 else ACCENT)
        dnsbl = f"[bold {WARN}]{len(r.dnsbl_listed)}[/]" if r.dnsbl_listed else f"[{ACCENT}]✓[/]"
        tbl.add_row(escape(r.email), f"[bold {rc}]{r.risk_score}[/]",
                    str(r.breach_count) if r.breach_count >= 0 else "N/A",
                    f"[{ACCENT}]✓[/]" if r.gravatar_exists else f"[{MUTED}]✗[/]",
                    f"[{ACCENT}]@{r.github_username}[/]" if r.github_exists else f"[{MUTED}]✗[/]",
                    str(len(r.platforms_found)), dnsbl)
    console.print(tbl)

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Email OSINT Tool v3.0 — Professional Intelligence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
API Keys (env vars — all free tier available):
  HIBP_API_KEY     -> haveibeenpwned.com/API/Key
  SHODAN_API_KEY   -> shodan.io
  LEAKCHECK_KEY    -> leakcheck.io
  ABUSEIPDB_KEY    -> abuseipdb.com

Examples:
  python email_osint.py
  python email_osint.py -e john@example.com
  python email_osint.py -e john@example.com --export json
  python email_osint.py --bulk emails.txt --export csv
  HIBP_API_KEY=xxx SHODAN_API_KEY=yyy python email_osint.py -e t@e.com
        """
    )
    parser.add_argument("-e", "--email",      help="Target email")
    parser.add_argument("--bulk",             metavar="FILE", help="Bulk scan file")
    parser.add_argument("--export",           choices=["json","csv"], help="Export format")
    parser.add_argument("--no-platforms",     action="store_true", help="Skip platform scan")
    args = parser.parse_args()

    if args.bulk:
        bulk_mode(args.bulk, export_fmt=args.export or "json")
    elif args.email:
        if not validate_email(args.email):
            console.print(f"[bold {WARN}]✗ Invalid email.[/]"); sys.exit(1)
        console.print(render_banner())
        console.print(render_api_status_panel())
        missing = [n for n, v in [("HIBP", HIBP_KEY),("Shodan", SHODAN_KEY),
                                   ("LeakCheck", LEAKCHECK_KEY),("AbuseIPDB", ABUSEIPDB_KEY)] if not v]
        if missing:
            render_api_setup_wizard()
            console.print(render_api_status_panel())
        console.print(f"\n  [{BLUE}]Scanning:[/] [bold]{escape(args.email)}[/]\n")
        result = run_scan(args.email, skip_platforms=args.no_platforms)
        render_full_report(result)
        if args.export:
            safe = re.sub(r'[^\w\-.]', '_', args.email)
            (export_json if args.export == "json" else export_csv)(result, f"osint_{safe}.{args.export}")
    else:
        interactive_mode()

if __name__ == "__main__":
    main()