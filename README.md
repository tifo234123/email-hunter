# 📧 Email OSINT Tool v3.0

> **Professional Email Intelligence Platform** — by Tifo

A powerful, terminal-based OSINT tool that aggregates intelligence from 14+ data sources to build a complete profile around any email address. Breach history, DNS analysis, platform footprint, threat intel, risk scoring — all in one shot.

---

## ✨ Features

| Category | What it does |
|---|---|
| 🔐 **Breach Intelligence** | HaveIBeenPwned (breaches + pastes), LeakCheck API |
| 👤 **Identity Correlation** | GitHub profile, repos, gists, orgs & activity |
| 🌐 **Domain Analysis** | DNS / MX / SPF / DKIM / DMARC / BIMI / DNSSEC |
| 🏢 **WHOIS** | Registrar, creation date, expiry, org, country |
| 🌍 **IP & ASN** | Geolocation, ASN, reverse DNS of the mail server |
| 🔍 **Shodan** | Open ports, vulnerabilities, banners on the mail server |
| 📸 **Wayback Machine** | Historical domain snapshots |
| 🦶 **Platform Footprint** | 30+ sites checked via username correlation |
| 🚫 **Blacklist Check** | 9 DNSBL zones |
| 🛡️ **Threat Intel** | AbuseIPDB reputation score |
| ⚠️ **Risk Scoring** | Automated threat assessment (0–100) |
| 🗑️ **Disposable Detection** | Flags known throwaway email providers |
| 📦 **Bulk Mode** | Scan a full list from a text file |
| 💾 **Export** | JSON or CSV output |

---

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install rich requests dnspython python-whois
```

### 2. Run it

```bash
# Interactive mode (recommended for first use)
python email_osint.py

# Single target
python email_osint.py -e target@example.com

# Single target + export
python email_osint.py -e target@example.com --export json

# Bulk scan from file
python email_osint.py --bulk emails.txt --export csv

# Skip platform scan (faster)
python email_osint.py -e target@example.com --no-platforms
```

---

## 🔑 API Keys

All keys are **optional** but unlock the full power of the tool. All have free tiers.

| Key | Source | Unlocks |
|---|---|---|
| `HIBP_API_KEY` | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) | Breach & paste lookup |
| `SHODAN_API_KEY` | [shodan.io](https://account.shodan.io/) | Port/vuln scan on mail server |
| `LEAKCHECK_KEY` | [leakcheck.io](https://leakcheck.io/) | Additional breach database |
| `ABUSEIPDB_KEY` | [abuseipdb.com](https://www.abuseipdb.com/account/plans) | IP reputation / threat intel |

### Set keys via environment variables

**Linux / macOS:**
```bash
export HIBP_API_KEY=your_key_here
export SHODAN_API_KEY=your_key_here
export LEAKCHECK_KEY=your_key_here
export ABUSEIPDB_KEY=your_key_here
```

**Windows (CMD):**
```cmd
set HIBP_API_KEY=your_key_here
```

**Or inline:**
```bash
HIBP_API_KEY=xxx SHODAN_API_KEY=yyy python email_osint.py -e target@example.com
```

> 💡 The tool includes a built-in **API setup wizard** — if keys are missing when you launch, it will guide you through entering them for the session.

---

## 📂 Output

### JSON export
```bash
python email_osint.py -e user@example.com --export json
# → osint_user_example_com.json
```

### CSV export (great for bulk)
```bash
python email_osint.py --bulk emails.txt --export csv
# → bulk_osint_YYYYMMDD_HHMMSS.csv
```

CSV columns include: `email`, `risk_score`, `provider`, `disposable`, `breaches`, `pastes`, `gravatar`, `github`, `platforms`, `dnsbl`, `shodan_vulns`, `domain_age`, `ip_country`.

---

## 🛠️ Requirements

- Python 3.8+
- `rich` — terminal UI
- `requests` — HTTP calls
- `dnspython` — DNS resolution
- `python-whois` — WHOIS lookups

```bash
pip install rich requests dnspython python-whois
```

---

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security research purposes only**. Only scan email addresses you own or have explicit permission to investigate. The author is not responsible for any misuse.

---

## 👤 Author

Made by **Tifo** — aspiring cybersecurity engineer & pentester.
