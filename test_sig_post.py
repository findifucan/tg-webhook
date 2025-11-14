#!/usr/bin/env python3
# test_sig_post.py
# Usage: export WEBHOOK_SECRET='secret' (already set), then: python3 test_sig_post.py

import os, hmac, hashlib, base64, requests, json

WEBHOOK = "https://web-production-9ef7c3.up.railway.app/notify"
secret = os.environ.get("WEBHOOK_SECRET")
if not secret:
    print("ERROR: WEBHOOK_SECRET not set in env")
    raise SystemExit(1)

data = open("sample.json","rb").read()
s = secret.encode()

hexsig = hmac.new(s, data, hashlib.sha256).hexdigest()
hexsig_up = hexsig.upper()
b64sig = base64.b64encode(hmac.new(s, data, hashlib.sha256).digest()).decode()

candidates = [
    ("raw-hex", hexsig),
    ("sha256-hex", "sha256=" + hexsig),
    ("hex-up", hexsig_up),
    ("sha256-hex-up", "sha256=" + hexsig_up),
    ("base64", b64sig),
    ("sha256-base64", "sha256=" + b64sig),
]

headers_base = {"Content-Type": "application/json"}

for tag, val in candidates:
    headers = headers_base.copy()
    headers["X-Webhook-Signature"] = val
    print("=== Trying:", tag, "header len:", len(val))
    try:
        r = requests.post(WEBHOOK, data=data, headers=headers, timeout=15)
        print("STATUS:", r.status_code)
        print("BODY:", r.text[:800])
    except Exception as e:
        print("ERROR:", e)
    print()
