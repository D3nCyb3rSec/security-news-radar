#!/usr/bin/env python3
"""Security news and CVE aggregator with static HTML output and notifications."""

from __future__ import annotations

import argparse
import datetime as dt
import email.message
import email.utils
import html
import json
import os
import shutil
import smtplib
import sqlite3
import sys
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = Path(os.environ.get("SECURITY_NEWS_CONFIG", ROOT / "config.json"))
DB_PATH = Path(os.environ.get("SECURITY_NEWS_DB_PATH", ROOT / "data" / "security_news.sqlite"))
SITE_PATH = Path(os.environ.get("SECURITY_NEWS_SITE_PATH", ROOT / "public" / "index.html"))
USER_AGENT = "SecurityNewsAggregator/1.0 (+local)"
DEFAULT_HTTP_TIMEOUT = 45
DEFAULT_HTTP_RETRIES = 4
DEFAULT_LOGO = ROOT / "assets" / "security-news-radar-logo-max-de.png"
DEFAULT_MOBILE_LOGO = ROOT / "assets" / "security-news-radar-logo.png"
DEFAULT_EN_LOGO = ROOT / "assets" / "security-news-radar-logo-max-en.png"

I18N = {
    "de": {
        "html_lang": "de",
        "title": "Security News Radar",
        "subtitle": "Aktuelle CVEs, bekannte Exploits und wichtige Cybersecurity-Meldungen.",
        "feed_description": "Aktuelle CVEs, bekannte Exploits und wichtige Cybersecurity-Meldungen.",
        "generated": "Generiert",
        "filters": "Filter",
        "entries": "Eintraege",
        "search_placeholder": "Thema suchen, z.B. ransomware, fortinet, zero-day",
        "all_sources": "Alle Quellen",
        "newest": "Neueste zuerst",
        "oldest": "Aelteste zuerst",
        "criticality": "Kritikalitaet zuerst",
        "criticality_low": "Niedrige Kritikalitaet zuerst",
        "system": "Systemmodus",
        "dark": "Darkmode",
        "light": "Lightmode",
        "reset": "x Filter zuruecksetzen",
        "empty": "Noch keine passenden Meldungen gefunden.",
        "rss": "RSS Feed",
        "language": "Sprache",
    },
    "en": {
        "html_lang": "en",
        "title": "Security News Radar",
        "subtitle": "Current CVEs, known exploits, and important cybersecurity updates.",
        "feed_description": "Current CVEs, known exploits, and important cybersecurity updates.",
        "generated": "Generated",
        "filters": "Filters",
        "entries": "Entries",
        "search_placeholder": "Search topic, e.g. ransomware, fortinet, zero-day",
        "all_sources": "All sources",
        "newest": "Newest first",
        "oldest": "Oldest first",
        "criticality": "Criticality first",
        "criticality_low": "Lowest criticality first",
        "system": "System mode",
        "dark": "Dark mode",
        "light": "Light mode",
        "reset": "x Reset filters",
        "empty": "No matching items found yet.",
        "rss": "RSS Feed",
        "language": "Language",
    },
}


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
        except (TypeError, ValueError):
            return None


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(
            f"Config fehlt: {path}\n"
            "Kopiere config.example.json nach config.json und passe Filter/Benachrichtigung an."
        )
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def http_get(
    url: str,
    *,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    retries: int = DEFAULT_HTTP_RETRIES,
    timeout: int = DEFAULT_HTTP_TIMEOUT,
) -> bytes:
    if params:
        separator = "&" if "?" in url else "?"
        url = f"{url}{separator}{urllib.parse.urlencode(params)}"
    request_headers = {"User-Agent": USER_AGENT}
    request_headers.update(headers or {})
    last_error: Exception | None = None
    retry_statuses = {429, 500, 502, 503, 504}
    if "services.nvd.nist.gov/rest/json/cves/2.0" in url:
        retry_statuses.add(404)
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers=request_headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in retry_statuses or attempt == retries:
                raise
            retry_after = exc.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                wait_seconds = min(int(retry_after), 120)
            else:
                wait_seconds = min(5 * (2**attempt), 120)
            time.sleep(wait_seconds)
        except urllib.error.URLError as exc:
            last_error = exc
            if attempt == retries:
                raise
            time.sleep(min(5 * (2**attempt), 120))
    raise RuntimeError(f"HTTP request failed: {last_error}")


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            published TEXT,
            severity TEXT,
            cve TEXT,
            summary TEXT,
            tags TEXT,
            notified_at TEXT,
            first_seen TEXT NOT NULL
        )
        """
    )
    return conn


def normalize_text(value: str | None) -> str:
    return " ".join((value or "").split())


def stable_id(source: str, url: str, title: str) -> str:
    return f"{source}:{url or title}".lower()


def fetch_nvd(config: dict[str, Any]) -> list[dict[str, Any]]:
    days = int(config.get("lookback_days", 2))
    start = utc_now() - dt.timedelta(days=days)
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "lastModEndDate": utc_now().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    }
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    data = json.loads(
        http_get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers=headers,
            retries=int(config.get("nvd_retries", DEFAULT_HTTP_RETRIES)),
            timeout=int(config.get("nvd_timeout_seconds", DEFAULT_HTTP_TIMEOUT)),
        )
    )
    items: list[dict[str, Any]] = []
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        summary = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        severity = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key) or []
            if values:
                severity = values[0].get("cvssData", {}).get("baseSeverity") or values[0].get("baseSeverity", "")
                break
        items.append(
            {
                "id": f"nvd:{cve_id}",
                "source": "NVD CVE",
                "title": f"{cve_id}: {summary[:140]}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published": cve.get("published"),
                "severity": severity,
                "cve": cve_id,
                "summary": summary,
                "tags": ["cve", severity.lower()] if severity else ["cve"],
            }
        )
    return items


def fetch_cisa_kev(config: dict[str, Any]) -> list[dict[str, Any]]:
    data = json.loads(
        http_get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    )
    items: list[dict[str, Any]] = []
    cutoff = utc_now().date() - dt.timedelta(days=int(config.get("kev_lookback_days", config.get("lookback_days", 2))))
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        name = vuln.get("vulnerabilityName", "")
        notes = vuln.get("notes", "")
        date_added = vuln.get("dateAdded")
        if date_added:
            try:
                if dt.date.fromisoformat(date_added) < cutoff:
                    continue
            except ValueError:
                pass
        items.append(
            {
                "id": f"cisa-kev:{cve_id}",
                "source": "CISA KEV",
                "title": f"{cve_id}: {vendor} {product} - {name}",
                "url": notes if notes.startswith("http") else f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "published": f"{date_added}T00:00:00+00:00" if date_added else None,
                "severity": "KNOWN_EXPLOITED",
                "cve": cve_id,
                "summary": vuln.get("shortDescription", ""),
                "tags": ["cve", "exploited", "cisa-kev", vendor.lower(), product.lower()],
            }
        )
    return items


def fetch_rss(source: dict[str, Any]) -> list[dict[str, Any]]:
    raw = http_get(source["url"])
    root = ET.fromstring(raw)
    channel_items = root.findall(".//item")
    atom_items = root.findall("{http://www.w3.org/2005/Atom}entry")
    items: list[dict[str, Any]] = []
    for item in channel_items:
        title = normalize_text(item.findtext("title"))
        link = normalize_text(item.findtext("link"))
        published = normalize_text(item.findtext("pubDate"))
        summary = normalize_text(item.findtext("description"))
        items.append(
            {
                "id": stable_id(source["name"], link, title),
                "source": source["name"],
                "title": title,
                "url": link,
                "published": published,
                "severity": "",
                "cve": "",
                "summary": summary,
                "tags": ["news"],
            }
        )
    for item in atom_items:
        title = normalize_text(item.findtext("{http://www.w3.org/2005/Atom}title"))
        link_node = item.find("{http://www.w3.org/2005/Atom}link")
        link = link_node.attrib.get("href", "") if link_node is not None else ""
        published = normalize_text(
            item.findtext("{http://www.w3.org/2005/Atom}published")
            or item.findtext("{http://www.w3.org/2005/Atom}updated")
        )
        summary = normalize_text(
            item.findtext("{http://www.w3.org/2005/Atom}summary")
            or item.findtext("{http://www.w3.org/2005/Atom}content")
        )
        items.append(
            {
                "id": stable_id(source["name"], link, title),
                "source": source["name"],
                "title": title,
                "url": link,
                "published": published,
                "severity": "",
                "cve": "",
                "summary": summary,
                "tags": ["news"],
            }
        )
    return items


def matches_filters(item: dict[str, Any], config: dict[str, Any]) -> bool:
    filters = config.get("filters", {})
    include = [x.lower() for x in filters.get("include_keywords", [])]
    exclude = [x.lower() for x in filters.get("exclude_keywords", [])]
    min_severity = (filters.get("min_cvss_severity") or "").upper()
    text = " ".join(
        str(item.get(key, "")) for key in ("title", "summary", "source", "severity", "cve", "tags")
    ).lower()
    if exclude and any(keyword in text for keyword in exclude):
        return False
    if include and not any(keyword in text for keyword in include):
        return False
    if min_severity and item.get("source") == "NVD CVE":
        order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return order.get((item.get("severity") or "").upper(), 0) >= order.get(min_severity, 0)
    return True


def collect_items(config: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    errors: list[str] = []
    for source in config.get("sources", []):
        if not source.get("enabled", True):
            continue
        try:
            kind = source.get("type")
            if kind == "nvd":
                items.extend(fetch_nvd(config))
            elif kind == "cisa_kev":
                items.extend(fetch_cisa_kev(config))
            elif kind == "rss":
                items.extend(fetch_rss(source))
            else:
                errors.append(f"Unbekannter Quellentyp: {kind}")
            time.sleep(float(config.get("request_delay_seconds", 0.5)))
        except (urllib.error.URLError, TimeoutError, ValueError, ET.ParseError) as exc:
            errors.append(f"{source.get('name', source.get('type'))}: {exc}")
    filtered = [item for item in items if matches_filters(item, config)]
    if errors:
        print("Quellen mit Fehlern:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
    return filtered


def save_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    conn = db()
    new_items: list[dict[str, Any]] = []
    now = utc_now().isoformat()
    for item in items:
        item.setdefault("id", stable_id(item["source"], item.get("url", ""), item["title"]))
        exists = conn.execute("SELECT 1 FROM items WHERE id = ?", (item["id"],)).fetchone()
        conn.execute(
            """
            INSERT OR IGNORE INTO items
                (id, source, title, url, published, severity, cve, summary, tags, first_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item["id"],
                item.get("source", ""),
                item.get("title", ""),
                item.get("url", ""),
                item.get("published", ""),
                item.get("severity", ""),
                item.get("cve", ""),
                item.get("summary", ""),
                json.dumps(item.get("tags", []), ensure_ascii=False),
                now,
            ),
        )
        if not exists:
            new_items.append(item)
    conn.commit()
    conn.close()
    return new_items


def load_recent(limit: int = 120) -> list[sqlite3.Row]:
    conn = db()
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT * FROM items
        """
    ).fetchall()
    conn.close()
    return sorted(rows, key=sort_timestamp, reverse=True)[:limit]


def sort_timestamp(row: sqlite3.Row) -> float:
    published = parse_iso(row["published"])
    first_seen = parse_iso(row["first_seen"])
    value = published or first_seen
    return value.timestamp() if value else 0


def severity_score(value: str | None) -> int:
    return {
        "KNOWN_EXPLOITED": 50,
        "CRITICAL": 40,
        "HIGH": 30,
        "MEDIUM": 20,
        "LOW": 10,
    }.get((value or "").upper(), 0)


def render_rss(rows: list[sqlite3.Row], config: dict[str, Any]) -> None:
    site_url = str(config.get("site_url", "")).rstrip("/")
    feed_url = f"{site_url}/feed.xml" if site_url else "feed.xml"
    page_url = f"{site_url}/" if site_url else "index.html"
    items = []
    for row in rows[: int(config.get("rss_limit", 50))]:
        published = parse_iso(row["published"]) or parse_iso(row["first_seen"]) or utc_now()
        items.append(
            f"""
            <item>
              <title>{html.escape(row["title"])}</title>
              <link>{html.escape(row["url"])}</link>
              <guid isPermaLink="false">{html.escape(row["id"])}</guid>
              <pubDate>{published.strftime("%a, %d %b %Y %H:%M:%S %z")}</pubDate>
              <source>{html.escape(row["source"])}</source>
              <description>{html.escape(row["summary"] or "")}</description>
            </item>
            """
        )
    feed = textwrap.dedent(
        f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>{html.escape(config.get("rss_title", "Security News Radar"))}</title>
            <link>{html.escape(page_url)}</link>
            <description>Aktuelle CVEs, bekannte Exploits und wichtige Cybersecurity-Meldungen.</description>
            <language>de-DE</language>
            <lastBuildDate>{utc_now().strftime("%a, %d %b %Y %H:%M:%S %z")}</lastBuildDate>
            <atom:link xmlns:atom="http://www.w3.org/2005/Atom" href="{html.escape(feed_url)}" rel="self" type="application/rss+xml" />
            {''.join(items)}
          </channel>
        </rss>
        """
    )
    (SITE_PATH.parent / "feed.xml").write_text(feed, encoding="utf-8")


def render_site(config: dict[str, Any]) -> None:
    rows = load_recent(int(config.get("site_limit", 120)))
    generated = utc_now().strftime("%Y-%m-%d %H:%M UTC")
    filter_keywords = ", ".join(config.get("filters", {}).get("include_keywords", [])) or "keine"
    logo_path = Path(config.get("site_logo", DEFAULT_LOGO))
    mobile_logo_path = Path(config.get("site_logo_mobile", DEFAULT_MOBILE_LOGO))
    logo_url = ""
    mobile_logo_url = ""
    sources = sorted({row["source"] for row in rows})
    source_options = "".join(f'<option value="{html.escape(source)}">{html.escape(source)}</option>' for source in sources)
    cards = []
    for row in rows:
        severity = row["severity"] or "INFO"
        severity_class = severity.lower().replace("_", "-")
        summary = html.escape(row["summary"] or "")[:500]
        searchable = html.escape(f"{row['source']} {severity} {row['title']} {row['summary'] or ''}".lower())
        timestamp = sort_timestamp(row)
        criticality = severity_score(severity)
        cards.append(
            f"""
            <article class="item" data-source="{html.escape(row['source'])}" data-severity="{html.escape(severity)}" data-search="{searchable}" data-time="{timestamp}" data-criticality="{criticality}">
              <div class="meta">
                <span class="source">{html.escape(row['source'])}</span>
                <span class="severity {severity_class}">{html.escape(severity)}</span>
                <span>{html.escape(row['published'] or row['first_seen'])}</span>
              </div>
              <h2><a href="{html.escape(row['url'])}" target="_blank" rel="noreferrer">{html.escape(row['title'])}</a></h2>
              <p>{summary}</p>
            </article>
            """
        )
    SITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    for asset_path, assign_name in ((logo_path, "desktop"), (mobile_logo_path, "mobile")):
        if not asset_path.exists():
            continue
        logo_target = SITE_PATH.parent / "assets" / asset_path.name
        logo_target.parent.mkdir(parents=True, exist_ok=True)
        if asset_path.resolve() != logo_target.resolve():
            shutil.copy2(asset_path, logo_target)
        copied_url = f"assets/{urllib.parse.quote(asset_path.name)}"
        if assign_name == "desktop":
            logo_url = copied_url
        else:
            mobile_logo_url = copied_url
    render_rss(rows, config)
    mobile_logo_url = mobile_logo_url or logo_url
    hero_vars = []
    if logo_url:
        hero_vars.append(f"--hero-logo: url('{html.escape(logo_url)}')")
    if mobile_logo_url:
        hero_vars.append(f"--hero-logo-mobile: url('{html.escape(mobile_logo_url)}')")
    hero_style = f' style="{"; ".join(hero_vars)}"' if hero_vars else ""
    SITE_PATH.write_text(
        textwrap.dedent(
            f"""\
            <!doctype html>
            <html lang="de">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>Security News Radar</title>
              <link rel="alternate" type="application/rss+xml" title="Security News Radar RSS Feed" href="feed.xml">
              <style>
                :root {{
                  color-scheme: light;
                  --bg: #f6f7f9;
                  --panel: #ffffff;
                  --text: #151922;
                  --muted: #5b6472;
                  --line: #dfe3ea;
                  --accent: #0b6bcb;
                  --critical: #b42318;
                  --high: #c2410c;
                  --medium: #a16207;
                  --known: #7c2d12;
                  --success: #8fe83a;
                  --danger: #ff5f6d;
                  --header-bg: #ffffff;
                  --header-text: #151922;
                  --header-muted: #5b6472;
                  --page-gradient: linear-gradient(180deg, #edf4fb 0%, var(--bg) 360px);
                }}
                html[data-theme="dark"] {{
                  color-scheme: dark;
                  --bg: #101318;
                  --panel: #171b22;
                  --text: #eef2f7;
                  --muted: #a7b0be;
                  --line: #2b323d;
                  --header-bg: #080d14;
                  --header-text: #eef2f7;
                  --header-muted: #a7b0be;
                  --page-gradient: radial-gradient(circle at 80% -10%, rgba(28, 117, 255, 0.20), transparent 28rem), linear-gradient(180deg, #080d14 0%, var(--bg) 360px);
                }}
                @media (prefers-color-scheme: dark) {{
                  html:not([data-theme="light"]) {{
                    color-scheme: dark;
                    --bg: #101318;
                    --panel: #171b22;
                    --text: #eef2f7;
                    --muted: #a7b0be;
                    --line: #2b323d;
                    --header-bg: #080d14;
                    --header-text: #eef2f7;
                    --header-muted: #a7b0be;
                    --page-gradient: radial-gradient(circle at 80% -10%, rgba(28, 117, 255, 0.20), transparent 28rem), linear-gradient(180deg, #080d14 0%, var(--bg) 360px);
                  }}
                }}
                * {{ box-sizing: border-box; }}
                body {{
                  margin: 0;
                  font-family: Inter, Segoe UI, system-ui, sans-serif;
                  background: var(--page-gradient);
                  color: var(--text);
                }}
                header {{
                  background: var(--header-bg);
                  color: var(--header-text);
                }}
                .hero {{
                  width: 100%;
                  aspect-ratio: 1994 / 454;
                  background-image: var(--hero-logo);
                  background-position: center;
                  background-repeat: no-repeat;
                  background-size: contain;
                  background-color: #050910;
                  border-bottom: 1px solid rgba(143, 232, 58, 0.15);
                }}
                .hero-wrap {{
                  padding-top: 0;
                }}
                .wrap {{
                  width: min(1840px, calc(100% - 56px));
                  margin: 0 auto;
                }}
                .top {{
                  padding: 44px 0 28px;
                  display: flex;
                  align-items: center;
                  justify-content: space-between;
                  gap: 24px;
                }}
                .brand {{
                  display: grid;
                  gap: 8px;
                  min-width: 0;
                }}
                h1 {{
                  margin: 0;
                  font-size: clamp(34px, 4vw, 56px);
                  letter-spacing: 0;
                }}
                .sub {{
                  color: var(--header-muted);
                  font-size: clamp(17px, 1.5vw, 24px);
                  margin: 0;
                }}
                .rss-link {{
                  display: inline-flex;
                  align-items: center;
                  gap: 10px;
                  border: 1px solid rgba(143, 232, 58, 0.65);
                  border-radius: 8px;
                  color: var(--success);
                  background: rgba(143, 232, 58, 0.06);
                  padding: 16px 22px;
                  font-size: 22px;
                  text-decoration: none;
                  white-space: nowrap;
                }}
                main {{ padding: 24px 0 48px; }}
                .control-panel {{
                  border: 1px solid var(--line);
                  border-radius: 8px;
                  background: color-mix(in srgb, var(--panel) 86%, transparent);
                  overflow: hidden;
                  box-shadow: 0 18px 50px rgba(0, 0, 0, 0.18);
                }}
                .toolbar {{
                  display: flex;
                  flex-wrap: wrap;
                  gap: 28px;
                  padding: 28px 24px;
                  color: var(--muted);
                  border-bottom: 1px solid var(--line);
                  font-size: 20px;
                }}
                .toolbar strong {{
                  color: var(--success);
                  font-weight: 700;
                }}
                .filters {{
                  display: grid;
                  gap: 14px;
                  padding: 18px 24px 0;
                }}
                .search-row {{
                  display: grid;
                  grid-template-columns: 1fr;
                }}
                .filter-row {{
                  display: grid;
                  grid-template-columns: 1fr 1fr 1fr;
                  gap: 14px;
                }}
                input, select {{
                  width: 100%;
                  border: 1px solid var(--line);
                  border-radius: 8px;
                  padding: 14px 16px;
                  background: var(--panel);
                  color: var(--text);
                  font: inherit;
                }}
                .actions {{
                  display: flex;
                  flex-wrap: wrap;
                  gap: 14px;
                  padding: 16px 24px 24px;
                }}
                button {{
                  border: 1px solid var(--line);
                  border-radius: 8px;
                  background: var(--panel);
                  color: var(--text);
                  cursor: pointer;
                  font: inherit;
                  padding: 12px 16px;
                }}
                .reset {{
                  border-color: rgba(255, 95, 109, 0.75);
                  color: var(--danger);
                }}
                .toggle {{
                  border-color: rgba(29, 155, 240, 0.85);
                  color: #35a7ff;
                }}
                @media (max-width: 720px) {{
                  .filter-row {{ grid-template-columns: 1fr; }}
                  .wrap {{ width: min(100% - 28px, 1840px); }}
                  .hero {{
                    background-image: var(--hero-logo-mobile);
                    aspect-ratio: 1959 / 803;
                  }}
                  .hero-wrap {{ padding-top: 0; }}
                  .top {{
                    align-items: flex-start;
                    flex-direction: column;
                  }}
                  .rss-link {{ font-size: 18px; padding: 12px 16px; }}
                }}
                #items {{ margin-top: 20px; }}
                .item {{
                  background: var(--panel);
                  border: 1px solid var(--line);
                  border-radius: 8px;
                  padding: 18px;
                  margin-bottom: 12px;
                }}
                .meta {{
                  display: flex;
                  flex-wrap: wrap;
                  gap: 8px;
                  align-items: center;
                  color: var(--muted);
                  font-size: 13px;
                }}
                .source, .severity {{
                  border: 1px solid var(--line);
                  border-radius: 999px;
                  padding: 3px 8px;
                  color: var(--text);
                }}
                .critical {{ color: var(--critical); }}
                .high {{ color: var(--high); }}
                .medium {{ color: var(--medium); }}
                .known-exploited {{ color: var(--known); }}
                h2 {{ font-size: 19px; line-height: 1.35; margin: 12px 0 8px; }}
                a {{ color: var(--accent); text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
                p {{ color: var(--muted); line-height: 1.55; margin: 0; }}
              </style>
            </head>
            <body>
              <header>
                <div class="wrap hero-wrap">
                  <div class="hero"{hero_style}></div>
                </div>
                <div class="wrap top">
                  <div class="brand">
                    <h1>Security News Radar</h1>
                    <p class="sub">Aktuelle CVEs, bekannte Exploits und wichtige Cybersecurity-Meldungen.</p>
                  </div>
                  <a class="rss-link" href="feed.xml" type="application/rss+xml">RSS Feed</a>
                </div>
              </header>
              <main class="wrap">
                <section class="control-panel">
                  <div class="toolbar">
                    <span>Generiert: {generated}</span>
                    <span>Filter: {html.escape(filter_keywords)}</span>
                    <span id="count">Eintraege: <strong>{len(rows)}</strong></span>
                  </div>
                  <section class="filters" id="filters" aria-label="Seitensuche">
                    <div class="search-row">
                      <input id="query" type="search" placeholder="Thema suchen, z.B. ransomware, fortinet, zero-day">
                    </div>
                    <div class="filter-row">
                      <select id="source">
                        <option value="">Alle Quellen</option>
                        {source_options}
                      </select>
                      <select id="sort">
                        <option value="newest">Neueste zuerst</option>
                        <option value="oldest">Aelteste zuerst</option>
                        <option value="criticality">Kritikalitaet zuerst</option>
                        <option value="criticality-low">Niedrige Kritikalitaet zuerst</option>
                      </select>
                      <select id="theme">
                        <option value="system">Systemmodus</option>
                        <option value="dark">Darkmode</option>
                        <option value="light">Lightmode</option>
                      </select>
                    </div>
                  </section>
                  <div class="actions">
                    <button class="reset" id="reset" type="button">x Filter zuruecksetzen</button>
                  </div>
                </section>
                <section id="items">
                  {''.join(cards) if cards else '<p>Noch keine passenden Meldungen gefunden.</p>'}
                </section>
              </main>
              <script>
                const query = document.getElementById('query');
                const source = document.getElementById('source');
                const sort = document.getElementById('sort');
                const theme = document.getElementById('theme');
                const count = document.getElementById('count');
                const reset = document.getElementById('reset');
                const itemContainer = document.getElementById('items');
                const items = Array.from(document.querySelectorAll('.item'));
                const savedTheme = localStorage.getItem('security-news-theme') || 'system';
                theme.value = savedTheme;
                function applyTheme() {{
                  const value = theme.value;
                  if (value === 'system') {{
                    document.documentElement.removeAttribute('data-theme');
                  }} else {{
                    document.documentElement.dataset.theme = value;
                  }}
                  localStorage.setItem('security-news-theme', value);
                }}
                function applySort() {{
                  const ordered = [...items].sort((a, b) => {{
                    const leftTime = Number(a.dataset.time || 0);
                    const rightTime = Number(b.dataset.time || 0);
                    const leftCriticality = Number(a.dataset.criticality || 0);
                    const rightCriticality = Number(b.dataset.criticality || 0);
                    if (sort.value === 'oldest') {{
                      return leftTime - rightTime;
                    }}
                    if (sort.value === 'criticality') {{
                      return (rightCriticality - leftCriticality) || (rightTime - leftTime);
                    }}
                    if (sort.value === 'criticality-low') {{
                      return (leftCriticality - rightCriticality) || (rightTime - leftTime);
                    }}
                    return rightTime - leftTime;
                  }});
                  for (const item of ordered) {{
                    itemContainer.appendChild(item);
                  }}
                }}
                function applyFilters() {{
                  const q = query.value.trim().toLowerCase();
                  const s = source.value;
                  let visible = 0;
                  for (const item of items) {{
                    const matchesQuery = !q || item.dataset.search.includes(q);
                    const matchesSource = !s || item.dataset.source === s;
                    const show = matchesQuery && matchesSource;
                    item.hidden = !show;
                    if (show) visible += 1;
                  }}
                  count.innerHTML = `Eintraege: <strong>${{visible}}</strong>`;
                }}
                function refresh() {{
                  applySort();
                  applyFilters();
                }}
                applyTheme();
                refresh();
                query.addEventListener('input', applyFilters);
                source.addEventListener('change', applyFilters);
                sort.addEventListener('change', refresh);
                theme.addEventListener('change', applyTheme);
                reset.addEventListener('click', () => {{
                  query.value = '';
                  source.value = '';
                  sort.value = 'newest';
                  refresh();
                }});
              </script>
            </body>
            </html>
            """
        ),
        encoding="utf-8",
    )


def resolve_asset_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def copy_site_asset(output_dir: Path, asset_path: Path, extra_output_dirs: list[Path] | None = None) -> str:
    if not asset_path.exists():
        return ""
    for target_dir in [output_dir, *(extra_output_dirs or [])]:
        target = target_dir / "assets" / asset_path.name
        target.parent.mkdir(parents=True, exist_ok=True)
        if asset_path.resolve() != target.resolve():
            shutil.copy2(asset_path, target)
    return f"assets/{urllib.parse.quote(asset_path.name)}"


def language_logo_paths(config: dict[str, Any], language: str) -> tuple[Path, Path]:
    if language == "en":
        desktop = config.get("site_logo_en", DEFAULT_EN_LOGO)
    else:
        desktop = config.get("site_logo_de", config.get("site_logo", DEFAULT_LOGO))
    mobile = config.get("site_logo_mobile", DEFAULT_MOBILE_LOGO)
    desktop_path = resolve_asset_path(desktop)
    if not desktop_path.exists():
        desktop_path = resolve_asset_path(config.get("site_logo", DEFAULT_LOGO))
    mobile_path = resolve_asset_path(mobile)
    return desktop_path, mobile_path


def language_aspect_ratio(language: str) -> str:
    return "2169 / 631" if language == "en" else "2168 / 681"


def render_rss_file(rows: list[sqlite3.Row], config: dict[str, Any], output_dir: Path, language: str) -> None:
    text = I18N.get(language, I18N["de"])
    site_url = str(config.get("site_url", "")).rstrip("/")
    if site_url:
        if language in {"de", "en"}:
            page_url = f"{site_url}/{language}/"
            feed_url = f"{site_url}/{language}/feed.xml"
        else:
            page_url = f"{site_url}/"
            feed_url = f"{site_url}/feed.xml"
    else:
        page_url = "index.html"
        feed_url = "feed.xml"
    items = []
    for row in rows[: int(config.get("rss_limit", 50))]:
        published = parse_iso(row["published"]) or parse_iso(row["first_seen"]) or utc_now()
        items.append(
            f"""
            <item>
              <title>{html.escape(row["title"])}</title>
              <link>{html.escape(row["url"])}</link>
              <guid isPermaLink="false">{html.escape(row["id"])}</guid>
              <pubDate>{published.strftime("%a, %d %b %Y %H:%M:%S %z")}</pubDate>
              <source>{html.escape(row["source"])}</source>
              <description>{html.escape(row["summary"] or "")}</description>
            </item>
            """
        )
    feed = textwrap.dedent(
        f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>{html.escape(config.get("rss_title", text["title"]))}</title>
            <link>{html.escape(page_url)}</link>
            <description>{html.escape(text["feed_description"])}</description>
            <language>{'en-US' if language == 'en' else 'de-DE'}</language>
            <lastBuildDate>{utc_now().strftime("%a, %d %b %Y %H:%M:%S %z")}</lastBuildDate>
            <atom:link xmlns:atom="http://www.w3.org/2005/Atom" href="{html.escape(feed_url)}" rel="self" type="application/rss+xml" />
            {''.join(items)}
          </channel>
        </rss>
        """
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "feed.xml").write_text(feed, encoding="utf-8")


def render_language_site(
    rows: list[sqlite3.Row],
    config: dict[str, Any],
    language: str,
    output_path: Path,
    language_links: dict[str, str],
    root_dir: Path | None = None,
) -> None:
    text = I18N.get(language, I18N["de"])
    generated = utc_now().strftime("%Y-%m-%d %H:%M UTC")
    filter_keywords = ", ".join(config.get("filters", {}).get("include_keywords", [])) or "keine"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    desktop_logo, mobile_logo = language_logo_paths(config, language)
    extra_asset_dirs = [root_dir] if root_dir and root_dir != output_path.parent else []
    logo_url = copy_site_asset(output_path.parent, desktop_logo, extra_asset_dirs)
    mobile_logo_url = copy_site_asset(output_path.parent, mobile_logo, extra_asset_dirs) or logo_url
    render_rss_file(rows, config, output_path.parent, language)
    hero_vars = []
    if logo_url:
        hero_vars.append(f"--hero-logo: url('{html.escape(logo_url)}')")
    if mobile_logo_url:
        hero_vars.append(f"--hero-logo-mobile: url('{html.escape(mobile_logo_url)}')")
    hero_vars.append(f"--hero-aspect: {language_aspect_ratio(language)}")
    hero_style = f' style="{"; ".join(hero_vars)}"'
    sources = sorted({row["source"] for row in rows})
    source_options = "".join(f'<option value="{html.escape(source)}">{html.escape(source)}</option>' for source in sources)
    language_switch = " ".join(
        f'<a href="{html.escape(url)}" lang="{html.escape(code)}">{code.upper()}</a>'
        if code != language
        else f'<strong>{code.upper()}</strong>'
        for code, url in language_links.items()
    )
    cards = []
    for row in rows:
        severity = row["severity"] or "INFO"
        severity_class = severity.lower().replace("_", "-")
        summary = html.escape(row["summary"] or "")[:500]
        searchable = html.escape(f"{row['source']} {severity} {row['title']} {row['summary'] or ''}".lower())
        timestamp = sort_timestamp(row)
        criticality = severity_score(severity)
        cards.append(
            f"""
            <article class="item" data-source="{html.escape(row['source'])}" data-severity="{html.escape(severity)}" data-search="{searchable}" data-time="{timestamp}" data-criticality="{criticality}">
              <div class="meta">
                <span class="source">{html.escape(row['source'])}</span>
                <span class="severity {severity_class}">{html.escape(severity)}</span>
                <span>{html.escape(row['published'] or row['first_seen'])}</span>
              </div>
              <h2><a href="{html.escape(row['url'])}" target="_blank" rel="noreferrer">{html.escape(row['title'])}</a></h2>
              <p>{summary}</p>
            </article>
            """
        )
    page = textwrap.dedent(
        f"""\
        <!doctype html>
        <html lang="{html.escape(text['html_lang'])}">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>{html.escape(text['title'])}</title>
          <link rel="alternate" type="application/rss+xml" title="{html.escape(text['title'])} RSS Feed" href="feed.xml">
          <style>
            :root {{
              color-scheme: light;
              --bg: #f6f7f9;
              --panel: #ffffff;
              --text: #151922;
              --muted: #5b6472;
              --line: #dfe3ea;
              --accent: #0b6bcb;
              --critical: #b42318;
              --high: #c2410c;
              --medium: #a16207;
              --known: #7c2d12;
              --success: #8fe83a;
              --danger: #ff5f6d;
              --header-bg: #ffffff;
              --header-text: #151922;
              --header-muted: #5b6472;
              --page-gradient: linear-gradient(180deg, #edf4fb 0%, var(--bg) 360px);
            }}
            html[data-theme="dark"] {{
              color-scheme: dark;
              --bg: #101318;
              --panel: #171b22;
              --text: #eef2f7;
              --muted: #a7b0be;
              --line: #2b323d;
              --header-bg: #080d14;
              --header-text: #eef2f7;
              --header-muted: #a7b0be;
              --page-gradient: radial-gradient(circle at 80% -10%, rgba(28, 117, 255, 0.20), transparent 28rem), linear-gradient(180deg, #080d14 0%, var(--bg) 360px);
            }}
            @media (prefers-color-scheme: dark) {{
              html:not([data-theme="light"]) {{
                color-scheme: dark;
                --bg: #101318;
                --panel: #171b22;
                --text: #eef2f7;
                --muted: #a7b0be;
                --line: #2b323d;
                --header-bg: #080d14;
                --header-text: #eef2f7;
                --header-muted: #a7b0be;
                --page-gradient: radial-gradient(circle at 80% -10%, rgba(28, 117, 255, 0.20), transparent 28rem), linear-gradient(180deg, #080d14 0%, var(--bg) 360px);
              }}
            }}
            * {{ box-sizing: border-box; }}
            body {{
              margin: 0;
              font-family: Inter, Segoe UI, system-ui, sans-serif;
              background: var(--page-gradient);
              color: var(--text);
            }}
            header {{ background: var(--header-bg); color: var(--header-text); }}
            .hero {{
              width: 100%;
              aspect-ratio: var(--hero-aspect);
              background-image: var(--hero-logo);
              background-position: center;
              background-repeat: no-repeat;
              background-size: contain;
              background-color: #050910;
              border-bottom: 1px solid rgba(143, 232, 58, 0.15);
            }}
            .wrap {{ width: min(1840px, calc(100% - 56px)); margin: 0 auto; }}
            .top {{
              padding: 44px 0 28px;
              display: flex;
              align-items: center;
              justify-content: space-between;
              gap: 24px;
            }}
            .brand {{ display: grid; gap: 8px; min-width: 0; }}
            h1 {{ margin: 0; font-size: clamp(34px, 4vw, 56px); letter-spacing: 0; }}
            .sub {{ color: var(--header-muted); font-size: clamp(17px, 1.5vw, 24px); margin: 0; }}
            .header-actions {{ display: flex; align-items: center; flex-wrap: wrap; gap: 14px; justify-content: flex-end; }}
            .language-switch {{
              display: inline-flex;
              gap: 8px;
              align-items: center;
              color: var(--header-muted);
              font-size: 17px;
            }}
            .language-switch a, .language-switch strong {{
              border: 1px solid var(--line);
              border-radius: 8px;
              padding: 9px 11px;
              text-decoration: none;
            }}
            .language-switch strong {{ color: var(--success); }}
            .rss-link {{
              display: inline-flex;
              align-items: center;
              gap: 10px;
              border: 1px solid rgba(143, 232, 58, 0.65);
              border-radius: 8px;
              color: var(--success);
              background: rgba(143, 232, 58, 0.06);
              padding: 16px 22px;
              font-size: 22px;
              text-decoration: none;
              white-space: nowrap;
            }}
            main {{ padding: 24px 0 48px; }}
            .control-panel {{
              border: 1px solid var(--line);
              border-radius: 8px;
              background: color-mix(in srgb, var(--panel) 86%, transparent);
              overflow: hidden;
              box-shadow: 0 18px 50px rgba(0, 0, 0, 0.18);
            }}
            .toolbar {{
              display: flex;
              flex-wrap: wrap;
              gap: 28px;
              padding: 28px 24px;
              color: var(--muted);
              border-bottom: 1px solid var(--line);
              font-size: 20px;
            }}
            .toolbar strong {{ color: var(--success); font-weight: 700; }}
            .filters {{ display: grid; gap: 14px; padding: 18px 24px 0; }}
            .search-row {{ display: grid; grid-template-columns: 1fr; }}
            .filter-row {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; }}
            input, select {{
              width: 100%;
              border: 1px solid var(--line);
              border-radius: 8px;
              padding: 14px 16px;
              background: var(--panel);
              color: var(--text);
              font: inherit;
            }}
            .actions {{ display: flex; flex-wrap: wrap; gap: 14px; padding: 16px 24px 24px; }}
            button {{
              border: 1px solid var(--line);
              border-radius: 8px;
              background: var(--panel);
              color: var(--text);
              cursor: pointer;
              font: inherit;
              padding: 12px 16px;
            }}
            .reset {{ border-color: rgba(255, 95, 109, 0.75); color: var(--danger); }}
            @media (max-width: 720px) {{
              .filter-row {{ grid-template-columns: 1fr; }}
              .wrap {{ width: min(100% - 28px, 1840px); }}
              .hero {{
                background-image: var(--hero-logo-mobile);
                aspect-ratio: 1959 / 803;
              }}
              .top {{ align-items: flex-start; flex-direction: column; }}
              .header-actions {{ justify-content: flex-start; }}
              .rss-link {{ font-size: 18px; padding: 12px 16px; }}
            }}
            #items {{ margin-top: 20px; }}
            .item {{
              background: var(--panel);
              border: 1px solid var(--line);
              border-radius: 8px;
              padding: 18px;
              margin-bottom: 12px;
            }}
            .meta {{
              display: flex;
              flex-wrap: wrap;
              gap: 8px;
              align-items: center;
              color: var(--muted);
              font-size: 13px;
            }}
            .source, .severity {{
              border: 1px solid var(--line);
              border-radius: 999px;
              padding: 3px 8px;
              color: var(--text);
            }}
            .critical {{ color: var(--critical); }}
            .high {{ color: var(--high); }}
            .medium {{ color: var(--medium); }}
            .known-exploited {{ color: var(--known); }}
            h2 {{ font-size: 19px; line-height: 1.35; margin: 12px 0 8px; }}
            a {{ color: var(--accent); text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            p {{ color: var(--muted); line-height: 1.55; margin: 0; }}
          </style>
        </head>
        <body>
          <header>
            <div class="wrap"><div class="hero"{hero_style}></div></div>
            <div class="wrap top">
              <div class="brand">
                <h1>{html.escape(text['title'])}</h1>
                <p class="sub">{html.escape(text['subtitle'])}</p>
              </div>
              <div class="header-actions">
                <nav class="language-switch" aria-label="{html.escape(text['language'])}">{language_switch}</nav>
                <a class="rss-link" href="feed.xml" type="application/rss+xml">{html.escape(text['rss'])}</a>
              </div>
            </div>
          </header>
          <main class="wrap">
            <section class="control-panel">
              <div class="toolbar">
                <span>{html.escape(text['generated'])}: {generated}</span>
                <span>{html.escape(text['filters'])}: {html.escape(filter_keywords)}</span>
                <span id="count">{html.escape(text['entries'])}: <strong>{len(rows)}</strong></span>
              </div>
              <section class="filters" id="filters" aria-label="{html.escape(text['filters'])}">
                <div class="search-row">
                  <input id="query" type="search" placeholder="{html.escape(text['search_placeholder'])}">
                </div>
                <div class="filter-row">
                  <select id="source">
                    <option value="">{html.escape(text['all_sources'])}</option>
                    {source_options}
                  </select>
                  <select id="sort">
                    <option value="newest">{html.escape(text['newest'])}</option>
                    <option value="oldest">{html.escape(text['oldest'])}</option>
                    <option value="criticality">{html.escape(text['criticality'])}</option>
                    <option value="criticality-low">{html.escape(text['criticality_low'])}</option>
                  </select>
                  <select id="theme">
                    <option value="system">{html.escape(text['system'])}</option>
                    <option value="dark">{html.escape(text['dark'])}</option>
                    <option value="light">{html.escape(text['light'])}</option>
                  </select>
                </div>
              </section>
              <div class="actions">
                <button class="reset" id="reset" type="button">{html.escape(text['reset'])}</button>
              </div>
            </section>
            <section id="items">
              {''.join(cards) if cards else f'<p>{html.escape(text["empty"])}</p>'}
            </section>
          </main>
          <script>
            const query = document.getElementById('query');
            const source = document.getElementById('source');
            const sort = document.getElementById('sort');
            const theme = document.getElementById('theme');
            const count = document.getElementById('count');
            const reset = document.getElementById('reset');
            const itemContainer = document.getElementById('items');
            const items = Array.from(document.querySelectorAll('.item'));
            const entriesLabel = {json.dumps(text['entries'])};
            const savedTheme = localStorage.getItem('security-news-theme') || 'system';
            theme.value = savedTheme;
            function applyTheme() {{
              const value = theme.value;
              if (value === 'system') {{
                document.documentElement.removeAttribute('data-theme');
              }} else {{
                document.documentElement.dataset.theme = value;
              }}
              localStorage.setItem('security-news-theme', value);
            }}
            function applySort() {{
              const ordered = [...items].sort((a, b) => {{
                const leftTime = Number(a.dataset.time || 0);
                const rightTime = Number(b.dataset.time || 0);
                const leftCriticality = Number(a.dataset.criticality || 0);
                const rightCriticality = Number(b.dataset.criticality || 0);
                if (sort.value === 'oldest') {{
                  return leftTime - rightTime;
                }}
                if (sort.value === 'criticality') {{
                  return (rightCriticality - leftCriticality) || (rightTime - leftTime);
                }}
                if (sort.value === 'criticality-low') {{
                  return (leftCriticality - rightCriticality) || (rightTime - leftTime);
                }}
                return rightTime - leftTime;
              }});
              for (const item of ordered) {{
                itemContainer.appendChild(item);
              }}
            }}
            function applyFilters() {{
              const q = query.value.trim().toLowerCase();
              const s = source.value;
              let visible = 0;
              for (const item of items) {{
                const matchesQuery = !q || item.dataset.search.includes(q);
                const matchesSource = !s || item.dataset.source === s;
                const show = matchesQuery && matchesSource;
                item.hidden = !show;
                if (show) visible += 1;
              }}
              count.innerHTML = `${{entriesLabel}}: <strong>${{visible}}</strong>`;
            }}
            function refresh() {{
              applySort();
              applyFilters();
            }}
            applyTheme();
            refresh();
            query.addEventListener('input', applyFilters);
            source.addEventListener('change', applyFilters);
            sort.addEventListener('change', refresh);
            theme.addEventListener('change', applyTheme);
            reset.addEventListener('click', () => {{
              query.value = '';
              source.value = '';
              sort.value = 'newest';
              refresh();
            }});
          </script>
        </body>
        </html>
        """
    )
    output_path.write_text(page, encoding="utf-8")


def render_site(config: dict[str, Any]) -> None:
    rows = load_recent(int(config.get("site_limit", 120)))
    languages = [lang for lang in config.get("languages", ["de", "en"]) if lang in I18N]
    if not languages:
        languages = ["de"]
    default_language = config.get("default_language", languages[0])
    if default_language not in languages:
        default_language = languages[0]
    root_dir = SITE_PATH.parent
    for language in languages:
        language_dir = root_dir / language
        links = {code: ("./" if code == language else f"../{code}/") for code in languages}
        render_language_site(rows, config, language, language_dir / "index.html", links, root_dir)
    root_links = {code: (f"{code}/" if code != default_language else "index.html") for code in languages}
    render_language_site(rows, config, default_language, SITE_PATH, root_links, root_dir)
    print(
        "Sprachseiten: "
        + ", ".join(str(root_dir / language / "index.html") for language in languages)
    )


def build_digest(items: list[dict[str, Any]], config: dict[str, Any]) -> str:
    title = config.get("digest_title", "Security News Update")
    if not items:
        return f"{title}\n\nKeine neuen passenden Meldungen seit dem letzten Lauf."
    lines = [title, ""]
    for item in items[: int(config.get("notification_limit", 15))]:
        severity = f" [{item.get('severity')}]" if item.get("severity") else ""
        lines.append(f"- {item.get('source')}{severity}: {item.get('title')}")
        lines.append(f"  {item.get('url')}")
    return "\n".join(lines)


def send_telegram(text: str) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = urllib.parse.urlencode({"chat_id": chat_id, "text": text[:3900]}).encode()
    request = urllib.request.Request(url, data=payload, method="POST")
    with urllib.request.urlopen(request, timeout=30):
        pass


def send_email(text: str, config: dict[str, Any]) -> None:
    email_cfg = config.get("email", {})
    if not email_cfg.get("enabled"):
        return
    host = os.environ.get("SMTP_HOST") or email_cfg.get("host")
    port = int(os.environ.get("SMTP_PORT") or email_cfg.get("port", 587))
    username = os.environ.get("SMTP_USERNAME") or email_cfg.get("username")
    password = os.environ.get("SMTP_PASSWORD") or email_cfg.get("password")
    sender = os.environ.get("SMTP_FROM") or email_cfg.get("from")
    recipients = os.environ.get("SMTP_TO") or ",".join(email_cfg.get("to", []))
    if not all([host, sender, recipients]):
        return
    message = email.message.EmailMessage()
    message["Subject"] = config.get("digest_title", "Security News Update")
    message["From"] = sender
    message["To"] = recipients
    message.set_content(text)
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.starttls()
        if username and password:
            smtp.login(username, password)
        smtp.send_message(message)


def notify(new_items: list[dict[str, Any]], config: dict[str, Any]) -> None:
    text = build_digest(new_items, config)
    if not new_items and not config.get("notify_when_empty", False):
        return
    send_telegram(text)
    send_email(text, config)


def main() -> int:
    global DB_PATH, SITE_PATH

    parser = argparse.ArgumentParser(description="Security news aggregator")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--db-path", type=Path, default=DB_PATH)
    parser.add_argument("--site-output", type=Path, default=SITE_PATH)
    parser.add_argument("--no-notify", action="store_true")
    args = parser.parse_args()
    DB_PATH = args.db_path
    SITE_PATH = args.site_output
    config = load_config(args.config)
    items = collect_items(config)
    new_items = save_items(items)
    render_site(config)
    if not args.no_notify:
        notify(new_items, config)
    print(f"{len(items)} passende Meldungen verarbeitet, {len(new_items)} neu.")
    print(f"Webseite: {SITE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
