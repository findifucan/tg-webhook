#!/usr/bin/env python3
"""
job_finder.py (updated)
- Tries HTML scrape (existing method). If blocked (403) it falls back to Indeed RSS.
- Saves seen IDs to seen.json and posts new jobs to webhook URL.
- Requires: requests, beautifulsoup4, feedparser
"""

import requests, hashlib, hmac, json, os, time
from bs4 import BeautifulSoup
from datetime import datetime

try:
    import feedparser
except Exception:
    feedparser = None

# CONFIG
WEBHOOK_URL = os.environ.get("WEBHOOK_URL") or "https://web-production-9ef7c3.up.railway.app/notify"
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")   # optional
SEEN_FILE = os.path.join(os.path.dirname(__file__), "seen.json")
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}

# Search targets
HTML_SEARCH_URL = ("https://in.indeed.com/jobs?q=CEH+fresher+cyber+security&l=India&sort=date")
RSS_SEARCH_URL = ("https://in.indeed.com/rss?q=CEH+fresher+cyber+security&l=India")

def load_seen():
    try:
        with open(SEEN_FILE, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_seen(s):
    with open(SEEN_FILE, "w") as f:
        json.dump(list(s), f)

def compute_hmac(body_bytes, secret):
    return hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()

def post_to_webhook(job):
    payload = {
        "title": job["title"],
        "company": job.get("company",""),
        "location": job.get("location",""),
        "apply_link": job["link"],
        "description": job.get("summary",""),
        "questions":[
            {"q":"Why are you interested in this role?","a":"(Short 1-2 line personalized answer)"},
            {"q":"Mention CEH topics you practiced.","a":"Nmap, Burp, SQLi testing, OSINT, SIEM basics."}
        ]
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type":"application/json"}
    if WEBHOOK_SECRET:
        headers["X-Webhook-Signature"] = compute_hmac(body, WEBHOOK_SECRET)
    resp = requests.post(WEBHOOK_URL, data=body, headers=headers, timeout=20)
    return resp

def fetch_jobs_html():
    r = requests.get(HTML_SEARCH_URL, headers=HEADERS, timeout=15)
    if r.status_code == 403:
        raise requests.HTTPError("Forbidden", response=r)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    jobs = []
    for card in soup.select("a.tapItem, div.job_seen_beacon"):
        try:
            a = card.find("a", href=True) or card
            href = a.get("href")
            if not href:
                continue
            link = "https://in.indeed.com" + href if href.startswith("/") else href
            title = (card.select_one("h2.jobTitle") or card.select_one(".jobTitle") or card.get("aria-label") or "Job").get_text(strip=True)
            company = (card.select_one(".companyName") or card.select_one(".company") or "") 
            company = company.get_text(strip=True) if company else ""
            location = (card.select_one(".companyLocation") or card.select_one(".location") or "")
            location = location.get_text(strip=True) if location else ""
            summary = (card.select_one(".job-snippet") or card.select_one(".summary") or "")
            summary = summary.get_text(" ", strip=True) if summary else ""
            job_id = hashlib.sha256(link.encode()).hexdigest()[:16]
            jobs.append({"id":job_id,"title":title,"company":company,"location":location,"link":link,"summary":summary})
        except Exception:
            continue
    return jobs

def fetch_jobs_rss():
    if not feedparser:
        return []
    feed = feedparser.parse(RSS_SEARCH_URL)
    jobs = []
    for e in feed.entries:
        link = e.get("link")
        title = e.get("title","Job")
        summary = e.get("summary","")
        job_id = hashlib.sha256((link or title).encode()).hexdigest()[:16]
        jobs.append({"id":job_id,"title":title,"company":e.get("author",""),"location":"","link":link,"summary":summary})
    return jobs

def fetch_jobs():
    # try HTML first, fall back to RSS
    try:
        return fetch_jobs_html()
    except requests.HTTPError as he:
        # Forbidden or other HTTP error -> fallback to RSS
        print("HTML fetch failed:", he)
        if feedparser:
            print("Falling back to RSS...")
            return fetch_jobs_rss()
        else:
            print("feedparser not installed; cannot use RSS fallback.")
            return []
    except Exception as e:
        print("Fetch error:", e)
        return []

def main():
    print(f"[{datetime.utcnow().isoformat()}] Starting job check...")
    seen = load_seen()
    jobs = fetch_jobs()
    new = [j for j in jobs if j["id"] not in seen]
    if not new:
        print("No new jobs.")
        return
    for job in new[:10]:
        print("Posting:", job["title"], job["link"])
        try:
            r = post_to_webhook(job)
            print("Webhook:", r.status_code, r.text)
            if r.status_code == 200:
                seen.add(job["id"])
        except Exception as e:
            print("Post error:", e)
    save_seen(seen)
    print("Done.")

if __name__ == "__main__":
    main()
