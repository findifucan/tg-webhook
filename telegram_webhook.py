# telegram_webhook.py
# Simple Flask app: /, /health, /notify
# HMAC header expected in X-Webhook-Signature (raw hex)
import os, hmac, hashlib, json, logging
from flask import Flask, request, jsonify, abort

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("webhook")

app = Flask(__name__)

# environment variables
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")

@app.route("/", methods=["GET"])
def index():
    return (
        "<h1>Job Finder Webhook</h1>"
        "<p>Available endpoints: <b>/health</b>, <b>/notify</b> (POST)</p>"
        "<p>Service is running.</p>",
        200,
    )

@app.route("/health", methods=["GET"])
def health():
    return "ok", 200

def valid_signature(body_bytes, sig_header):
    if not WEBHOOK_SECRET:
        # if secret not set, accept (useful for testing)
        log.warning("WEBHOOK_SECRET not set in environment — skipping HMAC check")
        return False if sig_header else True
    # expected header: raw hex (64 chars)
    try:
        computed = hmac.new(WEBHOOK_SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()
        # accept raw hex (lowercase) OR "sha256="+hex
        if sig_header is None:
            return False
        sig = sig_header.strip()
        if sig == computed or sig.lower() == computed:
            return True
        if sig.startswith("sha256=") and sig.split("=",1)[1] == computed:
            return True
        return False
    except Exception as e:
        log.exception("signature check error")
        return False

@app.route("/notify", methods=["POST"])
def notify():
    body = request.get_data()  # raw bytes
    sig = request.headers.get("X-Webhook-Signature")
    log.info("Received /notify, sig=%s, len=%d", sig and sig[:8]+"...", len(body))

    # If WEBHOOK_SECRET present, require correct signature
    if WEBHOOK_SECRET:
        if not valid_signature(body, sig):
            log.warning("Bad signature: header=%s", sig)
            return jsonify({"error": "bad signature"}), 403

    # parse payload (defensive)
    try:
        payload = request.get_json(force=True)
    except Exception:
        payload = None

    # For testing, just log and return OK
    log.info("Payload: %s", json.dumps(payload, ensure_ascii=False)[:800] if payload else "<no-json>")

    # TODO: forward to Telegram using TG_BOT_TOKEN/TG_CHAT_ID
    # (your existing code probably does this; keep that logic here)
    return jsonify({"ok": True}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
