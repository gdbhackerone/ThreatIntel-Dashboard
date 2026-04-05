\
    #!/usr/bin/env python3
    """
    ThreatIntel-Dashboard fetcher.

    - Pulls RSS/Atom feeds
    - Filters into last 3 hours and last 24 hours
    - Classifies items into simple tags
    - Generates docs/data/latest.json and docs/data/latest.md
    - Optionally sends email if SMTP settings are configured
    """

    from __future__ import annotations

    import calendar
    import json
    import os
    import re
    import smtplib
    import ssl
    from collections import Counter, defaultdict
    from dataclasses import dataclass
    from datetime import datetime, timedelta, timezone
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from pathlib import Path
    from typing import Any, Dict, Iterable, List, Optional, Tuple

    import feedparser
    import requests

    ROOT = Path(__file__).resolve().parent
    DOCS = ROOT / "docs"
    DATA_DIR = DOCS / "data"
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    DEFAULT_FEEDS = [
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "category": "Global News"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "category": "Global News"},
        {"name": "KrebsOnSecurity", "url": "https://krebsonsecurity.com/feed/", "category": "Global News"},
        {"name": "SecurityWeek", "url": "https://feeds.feedburner.com/securityweek", "category": "Global News"},
        {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "category": "Global News"},
        {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml", "category": "Threat Research"},
        {"name": "CISA Alerts", "url": "https://www.cisa.gov/news-events/alerts.xml", "category": "National / Government"},
        {"name": "CERT-In Advisories", "url": "https://www.cert-in.org.in/RSSFeed.jsp", "category": "National / Government"},
        {"name": "Exploit-DB", "url": "https://www.exploit-db.com/rss.xml", "category": "Exploits"},
        {"name": "Packet Storm", "url": "https://packetstormsecurity.com/files/feed.xml", "category": "Exploits"},
        {"name": "HackerOne Blog", "url": "https://hackerone.com/blog.rss", "category": "Red Team / Offensive Security"},
        {"name": "The DFIR Report", "url": "https://thedfirreport.com/feed/", "category": "Threat Research"},
        {"name": "OSINTCurio.us", "url": "https://osintcurio.us/feed/", "category": "OSINT"},
        {"name": "IntelTechniques", "url": "https://inteltechniques.com/blog/feed/", "category": "OSINT"},
        {"name": "Red Team Village", "url": "https://redteamvillage.io/feed", "category": "Red Team / Offensive Security"},
    ]

    KEYWORD_TAGS = {
        "vuln": ["cve", "vulnerability", "patch", "zero-day", "zero day", "exploit", "xss", "rce", "privilege escalation"],
        "malware": ["malware", "ransomware", "trojan", "botnet", "loader", "worm", "rat", "stealer"],
        "phishing": ["phishing", "spear-phishing", "credential", "oauth", "login", "otp"],
        "apt": ["apt", "nation-state", "espionage", "campaign", "threat actor"],
        "osint": ["osint", "leak", "breach", "paste", "exposed", "dork", "public record"],
        "red-team": ["red team", "pentest", "payload", "lateral movement", "post-exploitation", "adversary emulation"],
        "india": ["cert-in", "india", "indian", "in", "upi", "rbi", "nic"],
        "ddos": ["ddos", "defacement", "botnet", "traffic flood"],
    }

    SEVERITY_WEIGHTS = {
        "vuln": 2,
        "malware": 2,
        "phishing": 1,
        "apt": 2,
        "osint": 1,
        "red-team": 1,
        "india": 1,
        "ddos": 1,
    }

    def utc_now() -> datetime:
        return datetime.now(timezone.utc)

    def ist_now() -> datetime:
        return utc_now().astimezone(timezone(timedelta(hours=5, minutes=30)))

    def load_config() -> Dict[str, Any]:
        config_path = ROOT / "config.json"
        if config_path.exists():
            with config_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        return {
            "feeds": DEFAULT_FEEDS,
            "email": {
                "enabled": False,
                "smtp_host": "",
                "smtp_port": 587,
                "smtp_username": "",
                "smtp_password": "",
                "smtp_from": "",
                "alert_email_to": "",
            },
        }

    def normalize_text(value: Any) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip()

    def entry_datetime(entry: Any) -> Optional[datetime]:
        ts = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
        if ts:
            try:
                return datetime.fromtimestamp(calendar.timegm(ts), tz=timezone.utc)
            except Exception:
                return None
        for key in ("published", "updated", "created"):
            raw = getattr(entry, key, None)
            if isinstance(raw, str) and raw:
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(raw)
                    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                except Exception:
                    pass
        return None

    def classify_item(title: str, summary: str, source: str, category: str) -> Tuple[List[str], int]:
        text = f"{title} {summary} {source} {category}".lower()
        tags: List[str] = []
        risk_score = 1

        for tag, words in KEYWORD_TAGS.items():
            if any(word in text for word in words):
                tags.append(tag)
                risk_score += SEVERITY_WEIGHTS.get(tag, 0)

        if category:
            cat = category.lower()
            if "osint" in cat and "osint" not in tags:
                tags.append("osint")
            if "red team" in cat and "red-team" not in tags:
                tags.append("red-team")
            if "government" in cat and "india" not in tags and ("india" in text or "cert-in" in text):
                tags.append("india")

        risk_score = max(1, min(5, risk_score))
        if not tags:
            tags = ["general"]
        return sorted(set(tags)), risk_score

    def fetch_feed(feed: Dict[str, str]) -> List[Dict[str, Any]]:
        url = feed["url"]
        parsed = feedparser.parse(url)
        items: List[Dict[str, Any]] = []

        for entry in getattr(parsed, "entries", []):
            dt = entry_datetime(entry)
            if not dt:
                continue

            title = normalize_text(getattr(entry, "title", ""))
            link = normalize_text(getattr(entry, "link", ""))
            summary = normalize_text(getattr(entry, "summary", getattr(entry, "description", "")))

            if not title or not link:
                continue

            items.append({
                "title": title,
                "link": link,
                "summary": summary[:500],
                "published_utc": dt.isoformat(),
                "published_local": dt.astimezone(ist_now().tzinfo).strftime("%Y-%m-%d %H:%M %Z"),
                "source": feed["name"],
                "category": feed.get("category", "Unclassified"),
            })
        return items

    def within_hours(item: Dict[str, Any], hours: int) -> bool:
        dt = datetime.fromisoformat(item["published_utc"])
        return dt >= utc_now() - timedelta(hours=hours)

    def build_digest(all_items: List[Dict[str, Any]]) -> Dict[str, Any]:
        windows = {"3h": [], "24h": []}
        for item in all_items:
            tags, risk_score = classify_item(item["title"], item.get("summary", ""), item["source"], item["category"])
            item["tags"] = tags
            item["risk_score"] = risk_score

            if within_hours(item, 24):
                windows["24h"].append(item.copy())
            if within_hours(item, 3):
                windows["3h"].append(item.copy())

        for section in windows:
            windows[section].sort(key=lambda x: x["published_utc"], reverse=True)

        sources = sorted({item["source"] for item in windows["24h"]})
        counts = Counter(item["category"] for item in windows["24h"])
        tag_counts = Counter(tag for item in windows["24h"] for tag in item["tags"])

        return {
            "generated_at_utc": utc_now().strftime("%Y-%m-%d %H:%M UTC"),
            "generated_at_ist": ist_now().strftime("%Y-%m-%d %H:%M IST"),
            "window_hours": {"3h": 3, "24h": 24},
            "source_count": len(sources),
            "sources": sources,
            "category_counts": dict(counts),
            "tag_counts": dict(tag_counts),
            "windows": windows,
        }

    def write_json(payload: Dict[str, Any]) -> Path:
        out = DATA_DIR / "latest.json"
        with out.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return out

    def write_markdown(payload: Dict[str, Any]) -> Path:
        out = DATA_DIR / "latest.md"
        lines = [
            "# ThreatIntel-Dashboard Digest",
            f"Generated: {payload['generated_at_ist']}",
            "",
            f"- Sources: {payload['source_count']}",
            f"- Last 3 hours: {len(payload['windows']['3h'])}",
            f"- Last 24 hours: {len(payload['windows']['24h'])}",
            "",
        ]
        for section in ("3h", "24h"):
            lines.extend([f"## Last {section}", ""])
            for item in payload["windows"][section]:
                tags = ", ".join(item["tags"])
                lines.append(f"- [{item['title']}]({item['link']})")
                lines.append(f"  - Source: {item['source']}")
                lines.append(f"  - Category: {item['category']}")
                lines.append(f"  - Published: {item['published_local']}")
                lines.append(f"  - Risk: {item['risk_score']}/5")
                lines.append(f"  - Tags: {tags}")
            lines.append("")
        lines.append("## Advisory")
        lines.append("- Remain vigilant.")
        lines.append("- Patch promptly.")
        lines.append("- Enforce MFA.")
        lines.append("- Watch SIEM/IDS/IPS and firewall telemetry.")
        out.write_text("\n".join(lines), encoding="utf-8")
        return out

    def build_email(payload: Dict[str, Any]) -> Tuple[str, str]:
        html = [f"<h2>ThreatIntel-Dashboard Digest</h2><p>Generated: {payload['generated_at_ist']}</p>"]
        html.append(f"<p>Sources: {payload['source_count']} | Last 3h: {len(payload['windows']['3h'])} | Last 24h: {len(payload['windows']['24h'])}</p>")
        for section in ("3h", "24h"):
            html.append(f"<h3>Last {section}</h3><ul>")
            for item in payload["windows"][section][:20]:
                html.append(
                    f"<li><strong>{item['title']}</strong> — {item['source']} — Risk {item['risk_score']}/5<br>"
                    f"<a href=\"{item['link']}\">{item['link']}</a><br>"
                    f"<em>{item['published_local']}</em><br>"
                    f"Tags: {', '.join(item['tags'])}</li><br>"
                )
            html.append("</ul>")
        html.append("""
        <hr>
        <p><strong>Advisory</strong>: Apply patches promptly, maintain tested backups, enforce MFA, and monitor SIEM/IDS/IPS/firewall logs continuously.</p>
        """)
        subject = f"ThreatIntel-Dashboard Digest — {payload['generated_at_ist']}"
        return subject, "\n".join(html)

    def send_email_if_configured(payload: Dict[str, Any], email_cfg: Dict[str, Any]) -> None:
        enabled = bool(email_cfg.get("enabled"))
        smtp_host = os.getenv("SMTP_HOST", email_cfg.get("smtp_host", ""))
        smtp_port = int(os.getenv("SMTP_PORT", str(email_cfg.get("smtp_port", 587)) or 587))
        smtp_username = os.getenv("SMTP_USERNAME", email_cfg.get("smtp_username", ""))
        smtp_password = os.getenv("SMTP_PASSWORD", email_cfg.get("smtp_password", ""))
        smtp_from = os.getenv("SMTP_FROM", email_cfg.get("smtp_from", ""))
        smtp_to = os.getenv("ALERT_EMAIL_TO", email_cfg.get("alert_email_to", ""))

        if not enabled:
            # Allow env-only configuration in CI without setting enabled in config.
            enabled = all([smtp_host, smtp_port, smtp_username, smtp_password, smtp_from, smtp_to])

        if not all([enabled, smtp_host, smtp_port, smtp_username, smtp_password, smtp_from, smtp_to]):
            print("[i] Email disabled or SMTP secrets not configured.")
            return

        subject, html = build_email(payload)
        text_lines = [
            "ThreatIntel-Dashboard Digest",
            f"Generated: {payload['generated_at_ist']}",
            f"Sources: {payload['source_count']}",
            f"Last 3h: {len(payload['windows']['3h'])}",
            f"Last 24h: {len(payload['windows']['24h'])}",
            "",
            "Advisory: Apply patches promptly, maintain tested backups, enforce MFA, and monitor SIEM/IDS/IPS/firewall logs continuously.",
        ]
        text = "\n".join(text_lines)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = smtp_to
        msg.attach(MIMEText(text, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))

        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.starttls(context=context)
            if smtp_username:
                server.login(smtp_username, smtp_password)
            server.sendmail(smtp_from, [smtp_to], msg.as_string())
        print(f"[+] Email sent to {smtp_to}")

    def main() -> None:
        config = load_config()
        feeds = config.get("feeds", DEFAULT_FEEDS)

        all_items: List[Dict[str, Any]] = []
        failures = []

        for feed in feeds:
            try:
                print(f"[i] Fetching {feed['name']} ...")
                items = fetch_feed(feed)
                all_items.extend(items)
            except Exception as exc:
                failures.append({"source": feed["name"], "error": str(exc)})
                print(f"[!] {feed['name']} failed: {exc}")

        payload = build_digest(all_items)
        payload["failures"] = failures
        payload["generated_at_unix"] = int(utc_now().timestamp())

        json_path = write_json(payload)
        md_path = write_markdown(payload)
        print(f"[+] Wrote {json_path}")
        print(f"[+] Wrote {md_path}")

        send_email_if_configured(payload, config.get("email", {}))

    if __name__ == "__main__":
        main()
