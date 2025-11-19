import requests
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta, timezone
import random
import string
from extensions import get_db
from flask_cors import CORS
from security import hash_password

# --- DB ---
db = get_db()
users_collection = db.users

# --- Blueprint ---
reset_password_bp = Blueprint("reset_password_bp", __name__, url_prefix="/api/auth")

# --- CORS Allowed Origins ---
allowed_origins = [
    "https://kredinou.com",
    "https://www.kredinou.com",
    "https://destinytch.com.ng",
    "http://localhost:8000",
    "http://127.0.0.1:8000"
]

CORS(
    reset_password_bp,
    resources={r"/api/*": {"origins": allowed_origins}},
    supports_credentials=True
)

# --- Brevo API config (hardcoded for testing ONLY) ---
BREVO_API_KEY = "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"  # Replace with a freshly generated key
BREVO_SENDER_EMAIL = "support@kredinou.com"
BREVO_SENDER_NAME = "KrediNou"

def send_reset_email(to_email, code):
    """Send OTP reset code via Brevo API"""
    subject = "KrediNou - Password Reset Code"
    body = f"""
Hello,

You requested a password reset. Use the following code to reset your password:

{code}

This code is valid for 10 minutes.

If you did not request this, please ignore this email.

Best regards,
KrediNou Support Team
"""
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": body
    }

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code in [200, 201, 202]:
        return True
    print(f"❌ Failed to send reset email: {response.status_code} {response.text}")
    return False


# --- Step 1: Request reset code ---
@reset_password_bp.route("/request-reset", methods=["POST"])
def request_reset():
    data = request.get_json()
    email = data.get("email")
    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    code = "".join(random.choices(string.digits, k=6))
    expiry = datetime.now(timezone.utc) + timedelta(minutes=10)

    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "reset_code": code,
            "reset_code_expiry": expiry,
            "reset_verified": False
        }}
    )

    if not send_reset_email(email, code):
        return jsonify({"error": "Failed to send reset email"}), 500

    return jsonify({"message": "Reset code sent to your email"}), 200


# --- Step 2: Verify reset code ---
@reset_password_bp.route("/verify-reset", methods=["POST"])
def verify_reset():
    data = request.get_json()
    email = data.get("email")
    code = data.get("code")

    if not email or not code:
        return jsonify({"error": "Email and code are required"}), 400

    user = users_collection.find_one({"email": email})
    if not user or "reset_code" not in user:
        return jsonify({"error": "Invalid or expired code"}), 400

    if user["reset_code"] != code:
        return jsonify({"error": "Incorrect code"}), 400

    expiry = user.get("reset_code_expiry")
    if not expiry:
        return jsonify({"error": "Code expired"}), 400
    if not isinstance(expiry, datetime):
        try:
            expiry = datetime.fromisoformat(str(expiry))
        except Exception as e:
            print(f"❌ Expiry parsing error: {e}")
            return jsonify({"error": "Invalid expiry format"}), 400

    if datetime.now(timezone.utc) > expiry.replace(tzinfo=timezone.utc):
        return jsonify({"error": "Code expired"}), 400

    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"reset_verified": True}}
    )

    return jsonify({"message": "Code verified. You can now reset your password."}), 200


# --- Step 3: Reset password ---
@reset_password_bp.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    email = data.get("email")
    new_password = data.get("password") or data.get("newPassword")

    if not email or not new_password:
        return jsonify({"error": "Email and password required"}), 400

    user = users_collection.find_one({"email": email})
    if not user or not user.get("reset_verified"):
        return jsonify({"error": "Unauthorized or invalid reset flow"}), 400

    hashed_pw = hash_password(new_password)

    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"password": hashed_pw},
         "$unset": {"reset_code": "", "reset_code_expiry": "", "reset_verified": ""}}
    )

    return jsonify({"message": "Password reset successful"}), 200
