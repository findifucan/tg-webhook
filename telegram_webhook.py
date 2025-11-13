#!/usr/bin/env python3
from flask import Flask, request, jsonify
import requests, os, html, hmac, hashlib
from datetime import datetime

TELEGRAM_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID  = os.environ.get("TG_CHAT_ID", "").strip()
WEBHOOK_SECRET    = os.environ.get("WEBHOOK_SECRET", "")  # optional

if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    raise SystemExit("Missing TG_BOT_TOKEN or TG_CHAT_ID")

API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
app = Flask(__name__)

def verify(req):
    if not WEBHOOK_SECRET:
        return True
    sig = req.headers.get("X-Webhook-Signature", "")
    body = req.get_data()
    expected = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)

def msg(payload):
    title = payload.get("title","New Job Posted")
    company = payload.get("company","")
    location = payload.get("location","")
    link = payload.get("apply_link","")
    description = payload.get("description","")
    questions = payload.get("questions",[])

    lines = []
    lines.append(f"<b>{html.escape(title)}</b>")
    lines.append(f"🏢 <b>{html.escape(company)}</b> — {html.escape(location)}")
    if description:
        lines.append(html.escape(description))
    if link:
        lines.append(f'<a href="{html.escape(link)}">Apply Here ➜</a>')
    if questions:
        lines.append("\n<b>Interview Q&A</b>")
        for i,q in enumerate(questions[:5],1):
            lines.append(f"\n{i}) <i>{html.escape(q['q'])}</i>\nAnswer: {html.escape(q['a'])}")
    lines.append(f"\n⏱ {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}")
    return "\n".join(lines)

@app.route("/health")
def health():
    return "ok",200

@app.route("/notify",methods=["POST"])
def notify():
    if not verify(request):
        return jsonify({"error":"bad signature"}),403
    payload=request.get_json(force=True)
    text=msg(payload)
    r=requests.post(API_URL, data={
        "chat_id":TELEGRAM_CHAT_ID,
        "text":text,
        "parse_mode":"HTML"
    })
    return jsonify({"ok":True}),200

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)))
