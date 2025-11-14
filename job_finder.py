#!/usr/bin/env python3
"""
job_finder.py

Purpose:
  - Poll job feeds for CEH / cybersecurity fresher openings.
  - Send newly-found jobs to a webhook (signed HMAC SHA256 raw-lower-hex).
  - Keep a local seen list to avoid duplicate notifications.

Usage:
  - Set env vars: WEBHOOK_URL, WEBHOOK_SECRET
  - Run manually: python3 job_finder.py
  - Run in GitHub Actions (workflow provided earlier) or via cron.

Notes:
  - The script uses RSS/Atom feeds (feedparser). If an HTML page must be scraped, it will attempt to follow redirects and find links containing 'apply' or 'apply now'.
  - Customize FEEDS list below for other job sources.
"""

from __future__ import annotations
import os
import json
import time
import hmac
import hashlib
import logging
from typing import List, Dict, Optional
import feedparser
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone

# ---- Configuration ----
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")  # e.g. https://web-production-9ef7c3.up.railway.app/notify
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET")  # must match Railway value
SEEN_FILE = "seen_jobs.json"
USER_AGENT = "job-finder-bot/1.0 (+https://example.com)"
TIMEOUT = 12  # seconds for HTTP requests

# Default feeds (you can add more). These are example Indeed RSS queries for India.
# If any feed requires authentication or blocks scraping, add other feeds or APIs.
FEEDS = [
    # Indeed India search RSS for "CEH fresher cyber security" (example)
    "https://in.indeed.com/rss?q=CEH+fresher+cyber+security&l=India",
    # Generic Google Jobs / other provider RSS can be added here if available
    # Add user-specific company job RSS URLs, Naukri/Monster RSS if available
]

# Keywords to match as relevant to CEH/cybersecurity fresher roles
KEYWORDS = [
    "ceh", "certified ethical hacker", "fresher", "entry level", "junior", "trainee",
    "cyber", "security", "information security", "infosec", "threat", "vulnerability",
    "analyst", "soc", "penetration", "penetration tester", "security engineer"
]

# Fallback interview Q&A (used when no new jobs, or you can always send)
FALLBACK_QA = [
    {"q": "What is CEH and what topics does it cover?", "a": "CEH (Certified Ethical Hacker) covers penetration testing, network and web app exploitation, reconnaissance, vulnerability assessment, and countermeasures to think like an attacker."},
    {"q": "Explain the difference between vulnerability assessment and penetration testing.", "a": "Vulnerability assessment finds and lists vulnerabilities (scanning). Penetration testing exploits vulnerabilities to demonstrate impact and prioritize fixes."},
    {"q": "What is SQL injection and one way to prevent it?", "a": "SQL injection occurs when untrusted input is concatenated into SQL queries. Prevent with parameterized queries (prepared statements) and input validation."},
    {"q": "What is XSS and its basic mitigation?", "a": "Cross-site scripting injects scripts into web pages. Mitigate by output-encoding, Content Security Policy, and proper input validation."},
    {"q": "What is a SOC and what's a common task for a SOC analyst?", "a": "Security Operations Center (SOC) monitors and responds to security incidents. Analysts triage alerts, investigate logs, and escalate incidents."},
]

# ---- Logging ----
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("job_finder")

# ---- Helpers ----

def load_seen() -> Dict[str, float]:
    try:
        with open(SEEN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_seen(seen: Dict[str, float]) -> None:
    with open(SEEN_FILE, "w", encoding="utf-8") as f:
        json.dump(seen, f, indent=2)

def compute_hmac_hex(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

def send_signed_webhook(webhook_url: str, payload_obj: dict) -> tuple:
    if not webhook_url:
        raise RuntimeError("WEBHOOK_URL not set")
    if not WEBHOOK_SECRET:
        raise RuntimeError("WEBHOOK_SECRET not set")
    # deterministic JSON bytes (no spaces)
    body_bytes = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig_hex = compute_hmac_hex(WEBHOOK_SECRET, body_bytes)
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": sig_hex,
        "User-Agent": USER_AGENT
    }
    try:
        r = requests.post(webhook_url, data=body_bytes, headers=headers, timeout=20)
        return r.status_code, r.text
    except Exception as e:
        return 0, f"exception:{e}"

def short_summary(text: str, word_limit: int = 55) -> str:
    words = text.replace("\n", " ").split()
    if len(words) <= word_limit:
        return " ".join(words)
    return " ".join(words[:word_limit]) + "..."

def looks_relevant(title: str, summary: str) -> bool:
    combined = (title + " " + summary).lower()
    for kw in KEYWORDS:
        if kw in combined:
            return True
    return False

def extract_apply_link(entry_link: str) -> str:
    """
    Try to return a direct apply link.
    Strategy:
     - Follow redirects (requests.get) and use final URL.
     - If page HTML contains an anchor or button with 'apply' text, return its href.
     - Otherwise return the feed's entry link.
    """
    try:
        headers = {"User-Agent": USER_AGENT}
        r = requests.get(entry_link, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        final = r.url
        # parse HTML searching for links/buttons containing 'apply'
        html = r.text
        soup = BeautifulSoup(html, "html.parser")
        # candidate anchors/buttons
        for a in soup.find_all(["a", "button"]):
            text = (a.get_text() or "").strip().lower()
            href = a.get("href") or ""
            if "apply" in text and href:
                href = href.strip()
                if href.startswith("/"):
                    # make absolute
                    from urllib.parse import urljoin
                    href = urljoin(final, href)
                return href
        # fallback to final URL
        return final
    except Exception as e:
        logger.debug("extract_apply_link error for %s: %s", entry_link, e)
        return entry_link

# ---- Main job fetch & notify ----

def fetch_from_feed(url: str) -> List[dict]:
    logger.info("Fetching feed: %s", url)
    try:
        parsed = feedparser.parse(url)
    except Exception as e:
        logger.warning("feedparser parse failed for %s: %s", url, e)
        return []

    items = []
    for entry in parsed.entries[:50]:  # limit to recent 50
        job = {}
        job_id = entry.get("id") or entry.get("guid") or entry.get("link") or entry.get("title")
        job["id"] = str(job_id)
        job["title"] = entry.get("title", "").strip()
        job["link"] = entry.get("link", "").strip()
        job["summary"] = entry.get("summary", entry.get("description", "")).strip()
        # try to get company/location if provided in feed
        job["company"] = entry.get("company") or ""
        job["location"] = entry.get("location") or entry.get("author") or ""
        # published time
        try:
            if "published_parsed" in entry and entry.published_parsed:
                job["published"] = int(time.mktime(entry.published_parsed))
        except Exception:
            job["published"] = int(time.time())
        items.append(job)
    return items

def build_payload_from_job(job: dict) -> dict:
    title = job.get("title", "No title")
    company = job.get("company", "") or ""
    loc = job.get("location", "") or ""
    link = job.get("link", "")
    # attempt to find a direct apply link
    apply_link = extract_apply_link(link) if link else ""
    summary = short_summary(job.get("summary", ""), word_limit=55)
    # Build 50-60 word short description: try to keep concise
    desc = summary
    # sample interview Q&A per job (can be enhanced using job role detection)
    sample_q = [
        {"q": "What is CEH?", "a": "CEH means Certified Ethical Hacker — focus on penetration testing, info-gathering, and defensive controls."},
        {"q": "How would you perform a basic network scan?", "a": "Use Nmap to discover hosts/open ports, then map services and versions for further testing."},
    ]
    payload = {
        "title": title,
        "company": company,
        "location": loc,
        "apply_link": apply_link,
        "description": desc,
        "questions": sample_q,
        "source": "feed",
        "fetched_at": datetime.now(timezone.utc).isoformat()
    }
    return payload

def find_jobs_and_notify():
    if not WEBHOOK_URL or not WEBHOOK_SECRET:
        logger.error("WEBHOOK_URL or WEBHOOK_SECRET not set; aborting.")
        return

    seen = load_seen()
    new_seen = dict(seen)
    any_sent = False
    found_jobs = []

    for feed in FEEDS:
        items = fetch_from_feed(feed)
        for job in items:
            jid = job["id"]
            if not jid:
                continue
            if jid in seen:
                continue
            # check relevance
            if not looks_relevant(job.get("title", ""), job.get("summary", "")):
                # skip if not matching keywords
                continue
            # Build payload and send
            payload = build_payload_from_job(job)
            status, text = send_signed_webhook(WEBHOOK_URL, payload)
            logger.info("Sent job %s -> status=%s", jid, status)
            if status == 200:
                any_sent = True
                new_seen[jid] = time.time()
                found_jobs.append({"id": jid, "title": job.get("title")})
            else:
                logger.warning("Failed to send job %s status=%s body=%s", jid, status, text)

    # Save updated seen list
    if new_seen != seen:
        save_seen(new_seen)

    # If no new jobs found and you want fallback Q&A, send one message (optional)
    if not any_sent:
        logger.info("No new jobs found; sending fallback interview Q&A.")
        fallback_payload = {
            "title": "No new CEH fresher jobs found — study Q&A",
            "company": "",
            "location": "",
            "apply_link": "",
            "description": "No fresh roles found this run. Here are important interview questions to practice.",
            "questions": FALLBACK_QA,
            "source": "fallback",
            "fetched_at": datetime.now(timezone.utc).isoformat()
        }
        status, text = send_signed_webhook(WEBHOOK_URL, fallback_payload)
        logger.info("Fallback Q&A sent -> status=%s", status)

# ---- CLI ----
if __name__ == "__main__":
    logger.info("Starting job_finder run")
    try:
        find_jobs_and_notify()
    except Exception as exc:
        logger.exception("Unhandled exception in job_finder: %s", exc)
