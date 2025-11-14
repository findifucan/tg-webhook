import os
import hmac
import hashlib
import json
import logging
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
log = logging.getLogger("webhook")
logging.basicConfig(level=logging.INFO)

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN")
TG_CHAT_ID = os.getenv("TG_CHAT_ID")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").encode()


def send_telegram(text):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log.error("Missing TG_BOT_TOKEN or TG_CHAT_ID")
        return False

    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    r = requests.post(url, data={"chat_id": TG_CHAT_ID, "text": text})
    return r.status_code == 200


def verify_signature(payload, header_sig):
    """Verify hex HMAC SHA256 signature."""
    if not header_sig:
        return False

    expected = hmac.new(WEBHOOK_SECRET, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header_sig, expected)


@app.route("/", methods=["GET"])
def index():
    return "Webhook Ready", 200


@app.route("/health", methods=["GET"])
def health():
    return "ok", 200


@app.route("/notify", methods=["POST"])
def notify():
    payload = request.data
    header_sig = request.headers.get("X-Webhook-Signature")

    log.info(f"Received /notify, header_sig={header_sig}")

    if not verify_signature(payload, header_sig):
        log.warning("Bad signature")
        return jsonify({"error": "bad signature"}), 403

    try:
        data = json.loads(payload.decode())
    except:
        return jsonify({"error": "invalid json"}), 400

    message = f"🔔 *New Job Update*\n\n" + json.dumps(data, indent=2)
    send_telegram(message)

    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
