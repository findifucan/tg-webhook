#!/usr/bin/env python3
"""
job_finder.py (updated: extracts likely direct apply links)
- Multi-source: Indeed (RSS fallback), Naukri, Internshala (best-effort).
- For each job found, fetch the job page and try to extract a direct 'apply' link.
- Posts payload to WEBHOOK_URL with optional HMAC header X-Webhook-Signature.
"""
import os, json, time, hashlib, hmac, requests
from datetime import datetime
from bs4 import BeautifulSoup

try:
    import feedparser
except Exception:
    feedparser = None

# CONFIG
WEBHOOK_URL = os.environ.get("WEBHOOK_URL") or "https://web-production-9ef7c3.up.railway.app/notify"
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
SEEN_FILE = os.path.join(os.path.dirname(__file__), "seen.json")
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}

INDEED_RSS = "https://in.indeed.com/rss?q=CEH+fresher+cyber+security&l=India"
NAUKRI_SEARCH = "https://www.naukri.com/cyber-security-fresher-jobs-in-india"
INTERNSHALA_SEARCH = "https://internshala.com/internships/it-software/internship"

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
        "title": job.get("title",""),
        "company": job.get("company",""),
        "location": job.get("location",""),
        "apply_link": job.get("apply_link", job.get("link","")),
        "description": job.get("summary",""),
        "questions":[
            {"q":"Why are you interested in this role?","a":"(Short personalized answer)"},
            {"q":"Mention CEH topics you practiced.","a":"Nmap, Burp, SQLi, OSINT, SIEM basics."}
        ]
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type":"application/json"}
    if WEBHOOK_SECRET:
        headers["X-Webhook-Signature"] = compute_hmac(body, WEBHOOK_SECRET)
    r = requests.post(WEBHOOK_URL, data=body, headers=headers, timeout=20)
    return r

def extract_apply_link(job_page_url):
    """Open the job page and try heuristics to find an 'apply' link."""
    try:
        r = requests.get(job_page_url, headers=HEADERS, timeout=12)
        r.raise_for_status()
        html = r.text
    except Exception:
        return job_page_url  # fallback to original link

    soup = BeautifulSoup(html, "html.parser")

    # 1) Common 'apply' button selectors
    selectors = [
        "a.apply, a.apply-now, a.applyBtn, a.apply-button, a.btn-apply, a#apply-button",
        "a[href*='apply'], button.apply, button[id*='apply']",
        "a[role='button'][href*='apply']",
    ]
    for sel in selectors:
        el = soup.select_one(sel)
        if el and el.get("href"):
            href = el.get("href").strip()
            if href.startswith("http"):
                return href
            elif href.startswith("/"):
                base = requests.utils.urlparse(job_page_url).scheme + "://" + requests.utils.urlparse(job_page_url).netloc
                return base + href

    # 2) Look for form with action including 'apply' or 'submit'
    form = soup.find("form", action=lambda a: a and ("apply" in a or "submit" in a))
    if form:
        action = form.get("action")
        if action:
            if action.startswith("http"):
                return action
            if action.startswith("/"):
                base = requests.utils.urlparse(job_page_url).scheme + "://" + requests.utils.urlparse(job_page_url).netloc
                return base + action
            return job_page_url

    # 3) meta refresh or og:url or canonical
    og = soup.find("meta", property="og:url")
    if og and og.get("content"):
        return og.get("content")
    canon = soup.find("link", rel="canonical")
    if canon and canon.get("href"):
        return canon.get("href")

    # 4) search for external application links (common providers)
    for provider in ["meetanshi","apply.workable.com","lever.co","greenhouse","timesjobs","shrm","naukri.com","internshala.com","linkedin.com"]:
        tag = soup.select_one(f"a[href*='{provider}']")
        if tag and tag.get("href"):
            return tag.get("href")

    # no special apply link found — return original page
    return job_page_url

def parse_rss_feed(rss_url):
    if not feedparser:
        return []
    feed = feedparser.parse(rss_url)
    jobs = []
    for e in feed.entries:
        link = e.get("link")
        title = e.get("title","Job")
        summary = e.get("summary","")
        job_id = hashlib.sha256((link or title).encode()).hexdigest()[:16]
        jobs.append({"id":job_id,"title":title,"company":e.get("author",""),"location":"","link":link,"summary":summary})
    return jobs

def parse_naukri():
    try:
        r = requests.get(NAUKRI_SEARCH, headers=HEADERS, timeout=12)
        r.raise_for_status()
    except Exception:
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    jobs = []
    for card in soup.select("article.jobTuple, div.jobTuple")[:40]:
        try:
            a = card.find("a", href=True)
            href = a.get("href") if a else None
            if not href:
                continue
            link = href if href.startswith("http") else "https://www.naukri.com" + href
            title = (card.select_one("a.title") or card.select_one("h2") or card).get_text(strip=True)
            company = (card.select_one(".company") or card.select_one(".companyInfo .subTitle") or "").get_text(strip=True)
            job_id = hashlib.sha256(link.encode()).hexdigest()[:16]
            jobs.append({"id":job_id,"title":title,"company":company,"location":"","link":link,"summary":""})
        except Exception:
            continue
    return jobs

def parse_internshala():
    try:
        r = requests.get(INTERNSHALA_SEARCH, headers=HEADERS, timeout=12)
        r.raise_for_status()
    except Exception:
        return []
    soup = BeautifulSoup(r.text, "html.parser")
    jobs = []
    for card in soup.select("div.internship_meta, div.item, div.internship")[:40]:
        try:
            title_tag = card.select_one("a.profile") or card.select_one(".heading_4_5")
            title = title_tag.get_text(strip=True) if title_tag else card.get_text(" ", strip=True)[:80]
            if "cyber" not in title.lower() and "security" not in title.lower():
                continue
            link_tag = card.find("a", href=True)
            href = link_tag.get("href") if link_tag else None
            if not href:
                continue
            link = "https://internshala.com" + href if href.startswith("/") else href
            job_id = hashlib.sha256(link.encode()).hexdigest()[:16]
            jobs.append({"id":job_id,"title":title,"company":"","location":"","link":link,"summary":""})
        except Exception:
            continue
    return jobs

def fetch_jobs():
    jobs = []
    # Indeed RSS first (reliable)
    if feedparser:
        try:
            jobs = parse_rss_feed(INDEED_RSS)
            if jobs:
                return jobs
        except Exception:
            pass
    # Naukri fallback
    try:
        naukri = parse_naukri()
        if naukri:
            return naukri
    except Exception:
        pass
    # Internshala fallback
    try:
        intern = parse_internshala()
        if intern:
            return intern
    except Exception:
        pass
    return jobs

def main():
    print(f"[{datetime.utcnow().isoformat()}] Starting job check...")
    seen = load_seen()
    jobs = fetch_jobs()
    if not jobs:
        print("No jobs fetched.")
        return
    new = [j for j in jobs if j["id"] not in seen]
    if not new:
        print("No new jobs.")
        return
    for j in new[:15]:
        print("Resolving apply link for:", j.get("title"), j.get("link"))
        try:
            apply_link = extract_apply_link(j.get("link"))
            j["apply_link"] = apply_link
            r = post_to_webhook(j)
            print("Posted:", r.status_code, r.text)
            if r.status_code == 200:
                seen.add(j["id"])
        except Exception as e:
            print("Post error:", e)
        time.sleep(2)
    save_seen(seen)
    print("Done.")

if __name__ == "__main__":
    main()
