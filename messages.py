from flask import Blueprint, request, jsonify
from flask_cors import CORS
from datetime import datetime
import cloudinary.uploader
import json
import requests
import base64

from extensions import get_db

messages_bp = Blueprint("messages", __name__)
db = get_db()
history_collection = db.email_history

ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "https://kredinou.com",
    "https://www.kredinou.com",
    "https://destinytch.com.ng",
    "https://www.destinytch.com.ng",
]

CORS(
    messages_bp,
    origins=ALLOWED_ORIGINS,
    supports_credentials=False,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)

@messages_bp.after_request
def after_request(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,PUT,POST,DELETE,OPTIONS"
    return response

# ========================
# Brevo / Sendinblue Config
# ========================
BREVO_API_KEY = "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"
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

@messages_bp.route("/send-email", methods=["POST"])
def send_email():
    try:
        # Get form data
        subject = request.form.get("subject")
        body = request.form.get("body")
        recipients = request.form.get("recipients")  # JSON string
        recipients = json.loads(recipients)

        if not subject or not body or not recipients:
            return jsonify({"error": "Missing fields"}), 400

        # Optional attachment
        attachment_url = None
        attachment_name = None
        attachment_content = None
        if "attachment" in request.files:
            file = request.files["attachment"]
            if file:
                upload_result = cloudinary.uploader.upload(file, resource_type="auto")
                attachment_url = upload_result.get("secure_url")
                attachment_name = file.filename
                attachment_content = requests.get(attachment_url).content

        # Resolve recipient emails
        recipient_emails = []
        if recipients == "all":
            users = db.users.find({}, {"email": 1})
            recipient_emails = [u["email"] for u in users if u.get("email")]
        else:
            for r in recipients:
                user = db.users.find_one({"_id": r})
                if user and user.get("email"):
                    recipient_emails.append(user["email"])

        if not recipient_emails:
            return jsonify({"error": "No valid recipients"}), 400

        headers = {"api-key": BREVO_API_KEY, "Content-Type": "application/json"}

        # Send emails individually to protect privacy
        for email in recipient_emails:
            payload = {
                "sender": {"name": "KrediNou", "email": "support@kredinou.com"},
                "to": [{"email": email}],
                "subject": subject,
                "htmlContent": body
            }
            if attachment_content:
                payload["attachment"] = [
                    {
                        "content": base64.b64encode(attachment_content).decode("utf-8"),
                        "name": attachment_name
                    }
                ]
            resp = requests.post(BREVO_API_URL, headers=headers, json=payload)
            if resp.status_code >= 400:
                return jsonify({"error": f"Brevo API error for {email}: {resp.text}"}), 500

        # Log history
        history_collection.insert_one({
            "subject": subject,
            "recipients": recipient_emails if recipients != "all" else "all",
            "status": "Sent",
            "attachment_url": attachment_url,
            "sent_at": datetime.utcnow(),
        })

        return jsonify({"message": "Email sent successfully!"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@messages_bp.route("/history", methods=["GET"])
def get_history():
    try:
        history = list(history_collection.find().sort("sent_at", -1).limit(20))
        for h in history:
            h["_id"] = str(h["_id"])
            h["sent_at"] = h["sent_at"].strftime("%Y-%m-%d %H:%M:%S")
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
