import base64
from io import BytesIO
import os
import re
import uuid
import json
import logging
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from werkzeug.exceptions import HTTPException
from manager import manager_bp  # main directory
from users import users_bp 
from wallet import wallet_bp  # adjust path as needed
from config import Config
from user_dashboard import user_dashboard_bp
from werkzeug.middleware.proxy_fix import ProxyFix
from dashboard import dashboard_bp
from contact import contact_bp
from admin import admin_bp
from repayments import repayments_bp
from admin_repayments import admin_repayments_bp
from admin_withdrawals import admin_withdrawals_bp
from messages import messages_bp   
from dotenv import load_dotenv
from acct import acct_bp
from reset_password import reset_password_bp
import bcrypt
import jwt
import cloudinary
from cloudinary.uploader import upload as cloudinary_upload, destroy as cloudinary_delete

from loans import loans_bp
from decorators import token_required
# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app,
     resources={r"/*": {"origins": [
         "http://localhost:8000",
         "http://127.0.0.1:8000",
         "https://kredinou.com",
         "https://www.kredinou.com",
         "https://destinytch.com.ng",
         "https://www.destinytch.com.ng"
     ]}},
     supports_credentials=False,  # disable unless you *need* cookies
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS")
    return response

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
# App config
app.config.update({
    "SECRET_KEY": os.getenv("SECRET_KEY"),
    "MAX_CONTENT_LENGTH": 20 * 1024 * 1024,  # 5MB upload limit
})

# Configure Cloudinary
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True,
)

ALLOWED_DOC_TYPES = ['image/jpeg', 'image/png', 'application/pdf']
MAX_DOC_SIZE = 20 * 1024 * 1024  # 5MB

# Import extensions after app is created
from extensions import mongo_client, get_db

# Database collections
db = get_db()
users_collection = db.users
loans_collection = db.loans

# Register blueprints



# Create indexes
def create_indexes():
    try:
        loans_collection.create_index([("userId", 1)])
        loans_collection.create_index([("applicationDate", -1)])
        loans_collection.create_index([("userId", 1), ("status", 1)])
        users_collection.create_index([("email", 1)], unique=True)
        users_collection.create_index([("phone", 1)], unique=True)
        app.logger.info("Database indexes created successfully")
    except Exception as e:
        app.logger.error(f"Failed to create database indexes: {str(e)}")

create_indexes()
# Utility functions
def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_password(pw: str, h: str) -> bool:
    return bcrypt.checkpw(pw.encode(), h.encode())

def generate_jwt_token(uid: str) -> str:
    payload = {
        "user_id": uid,
        "exp": datetime.now(timezone.utc) + timedelta(days=1)
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

def token_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify(error="Token missing"), 401
        token = auth.split(" ", 1)[1]
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            user = users_collection.find_one({"_id": data["user_id"]})
            if not user:
                return jsonify(error="User not found, sign in again"), 404
        except Exception as e:
            app.logger.error(f"Token validation error: {str(e)}")
            return jsonify(error="Token invalid"), 401
        return f(user, *args, **kwargs)
    return wrapper

# Error handlers
@app.errorhandler(Exception)
def handle_all(e):
    if isinstance(e, HTTPException):
        return jsonify(error=e.description), e.code
    app.logger.exception(e)
    return jsonify(error="Bad internet connection"), 500

def upload_base64_image(base64_string, folder, public_id=None):
    """Upload base64 image to Cloudinary"""
    try:
        if ',' in base64_string:
            base64_string = base64_string.split(',')[1]
        file_obj = BytesIO(base64.b64decode(base64_string))
        result = cloudinary_upload(

            file_obj,
            folder=folder,
            public_id=public_id,
            resource_type="image",
            transformation=[
                {'width': 500, 'height': 500, 'crop': 'fill'},
                {'quality': 'auto'}
            ]
        )
        return result
    except Exception as e:
        app.logger.error(f"Cloudinary upload failed: {str(e)}")
        return None

# Error Handler
@app.errorhandler(Exception)
def handle_exception(e):
    """Global error handler"""
    if isinstance(e, HTTPException):
        return jsonify({'error': e.description}), e.code
    app.logger.error(f"Unhandled exception: {str(e)}")
    return jsonify({'error': 'Bad internet connection'}), 500


import re
import uuid
import random
import string
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify

# --- Email utilities ---
def generate_verification_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_verification_email(email, first_name, verification_code):
    subject = "Welcome! Please Verify Your Email"
    body = f"""
    Hi {first_name},

    Welcome to KrediNou!

    To continue with your registration, please use the verification code below:

    Verification Code: {verification_code}

    This code will expire in 10 minutes.

    Thank you!
    """
    send_email(email, subject, body)  # Replace with your actual send_email function


import re
import uuid
import random
import string
from datetime import datetime, timezone, timedelta


import requests

# --- Brevo API configuration (hardcoded for testing) ---
BREVO_API_KEY = "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"  # Replace with your new key after revoking the old one
BREVO_SENDER_EMAIL = "support@kredinou.com"
BREVO_SENDER_NAME = "KrediNou"

def send_email(to_email, subject, body):
    """Send email via Brevo API."""
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
        print(f"Email sent to {to_email}")
    else:
        print(f"Failed to send email to {to_email}: {response.status_code} {response.text}")

# --- Email utilities ---
def generate_verification_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_verification_email(email, first_name, verification_code):
    subject = "Welcome! Please Verify Your Email"
    body = f"""
Hi {first_name},

Welcome to KrediNou!

To continue with your registration, please use the verification code below:

Verification Code: {verification_code}

This code will expire in 10 minutes.

Thank you!
"""
    send_email(email, subject, body)

# add near your other imports
from bson import ObjectId
from datetime import datetime
from werkzeug.utils import secure_filename

# You already imported cloudinary_upload and cloudinary_delete above.
# Add this route to your Flask app file (or in a blueprint).
@app.route("/api/user/upload-face-image", methods=["POST"])
def upload_face_image():
    try:
        # ---------- AUTH: extract user id from Bearer token ----------
        auth = request.headers.get("Authorization", "")
        user_id = None
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1]
            try:
                payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
                # try a few common claim keys
                user_id = payload.get("user_id") or payload.get("id") or payload.get("sub")
            except Exception as e:
                app.logger.debug(f"JWT decode failed: {e}")

        # If you have a token_required decorator that injects current user,
        # replace the above block with the decorator usage and read current user id.
        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401

        # ---------- Validate file ----------
        if "face_image" not in request.files:
            return jsonify({"error": "No file part 'face_image'"}), 400

        file = request.files["face_image"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        # Basic MIME type check
        if file.mimetype not in ("image/jpeg", "image/png", "image/webp"):
            return jsonify({"error": "Unsupported file type. Use JPG/PNG/WEBP."}), 400

        # Filename safety & optional size check (Flask app.config MAX_CONTENT_LENGTH will block >5MB)
        filename = secure_filename(file.filename)

        # ---------- Optionally delete previous Cloudinary image ----------
        # If you store the Cloudinary public_id in the user doc you can delete it directly.
        # If not, attempt to parse the public_id from the ing URL (best effort).
        user_doc = users_collection.find_one({"_id": ObjectId(user_id)}) if ObjectId.is_valid(user_id) else users_collection.find_one({"_id": user_id})
        prev_public_id = None
        if user_doc and user_doc.get("face_image", {}).get("url"):
            prev_url = user_doc["face_image"]["url"]
            # Try to extract public_id from URL: last two path segments often contain folder/.../public_id.ext
            # This is a best-effort extraction; if you store public_id separately, use that instead.
            m = re.search(r"/v\d+/(.+)\.(jpg|jpeg|png|webp)$", prev_url)
            if m:
                prev_public_id = m.group(1)  # e.g. users/<id>/verification/face_image

        # ---------- Upload to Cloudinary ----------
        # Create a stable/overwrite public_id path (overwrite=True) or add uuid to avoid caching issues
        public_id = f"users/{user_id}/verification/face_image"
        # If you prefer unique file instead of overwrite:
        # public_id = f"users/{user_id}/verification/face_image_{uuid.uuid4().hex}"

        # Use file.stream or file to upload
        upload_result = cloudinary_upload(
            file,
            folder=f"users/{user_id}/verification",
            public_id="face_image",
            overwrite=True,
            resource_type="image"
        )

        if not upload_result or not upload_result.get("secure_url"):
            return jsonify({"error": "Cloudinary upload failed"}), 500

        secure_url = upload_result["secure_url"]
        uploaded_at = datetime.now(timezone.utc)

        # ---------- Update MongoDB user doc ----------
        update = {
            "face_image.url": secure_url,
            "face_image.uploaded_at": uploaded_at
        }
        # perform update and return the updated document (if desired)
        if ObjectId.is_valid(user_id):
            updated_user = users_collection.find_one_and_update(
                {"_id": ObjectId(user_id)},
                {"$set": update},
                return_document=True
            )
        else:
            updated_user = users_collection.find_one_and_update(
                {"_id": user_id},
                {"$set": update},
                return_document=True
            )

        # ---------- Optionally delete previous Cloudinary file (best-effort) ----------
        # Only delete previous if it s and is different from the new one
        try:
            if prev_public_id:
                # cloudinary_delete expects the public_id without extension
                # e.g. "users/<id>/verification/face_image"
                # Ensure we don't delete the newly uploaded file (if names overlap and overwrite used, skip)
                # Since we overwrote the same public_id, don't destroy it.
                # If you used unique public_id strategy, uncomment the destroy call:
                # cloudinary_delete(prev_public_id, invalidate=True, resource_type="image")
                pass
        except Exception as e:
            app.logger.warning(f"Failed to delete old Cloudinary file: {e}")

        # ---------- Return new URL ----------
        return jsonify({
            "url": secure_url,
            "uploaded_at": uploaded_at.isoformat()
        }), 200

    except HTTPException as he:
        raise he
    except Exception as exc:
        app.logger.exception("Error uploading face image")
        return jsonify({"error": str(exc)}), 500
@app.route("/api/register", methods=["POST"])
def register():
    try:
        # Handle form data
        if request.content_type.startswith('multipart/form-data'):
            data = request.form.to_dict()
            files = request.files
        elif request.content_type == 'application/json':
            data = request.get_json()
            files = {}
        else:
            return jsonify({"error": "Content-Type must be multipart/form-data or application/json"}), 400

        # Required fields
        required_fields = ['first_name', 'last_name', 'email', 'phone', 'password',
                           'department', 'commune', 'address']
        missing_fields = [f for f in required_fields if f not in data or not data[f].strip()]
        if missing_fields:
            return jsonify({"error": f"Missing required fields: {', '.join(missing_fields)}"}), 400

        email = data['email'].strip().lower()
        user = users_collection.find_one({"email": email})

        # Allowed MIME types for documents
        allowed_types = ['image/jpeg', 'image/png', 'application/pdf']

        # Helper function to map uploaded files to real document names
        def get_document_type(file, index):
            name_map = {
                0: "ID Front",
                1: "ID Back",
            }
            if file.name == "proof_of_address":
                return "Proof of Address"
            return name_map.get(index, f"Document {index+1}")

        if user:
            # ing user: keep current status & verification_status
            ing_documents = user.get("documents", [])
            ing_face_image = user.get("face_image", {})

            update_fields = {
                "first_name": data.get("first_name", user.get("first_name")),
                "middle_name": data.get("middle_name", user.get("middle_name", "")),
                "last_name": data.get("last_name", user.get("last_name")),
                "phone": data.get("phone", user.get("phone")),
                "password": hash_password(data.get("password")) if data.get("password") else user.get("password"),
                "department": data.get("department", user.get("department")),
                "commune": data.get("commune", user.get("commune")),
                "address": data.get("address", user.get("address")),
                "updated_at": datetime.now(timezone.utc),
                "documents": ing_documents,
                "face_image": ing_face_image,
                "loan_limit": user.get("loan_limit", 100000),
                "status": user.get("status", "pending_verification"),
                "verification_status": user.get("verification_status", "unverified")
            }

            # Handle new face image upload
            if "face_image" in files:
                file = files["face_image"]
                if file.filename:
                    result = cloudinary_upload(
                        file,
                        folder=f"users/{user['_id']}/verification",
                        public_id="face_image",
                        overwrite=True,
                        resource_type="image"
                    )
                    if result and result.get("secure_url"):
                        update_fields["face_image"] = {
                            "url": result["secure_url"],
                            "uploaded_at": datetime.now(timezone.utc)
                        }

            # Handle document uploads
            doc_files = files.getlist("document[]") or files.getlist("document") or []
            if "proof_of_address" in files:
                doc_files.append(files["proof_of_address"])

            for i, file in enumerate(doc_files):
                if file and file.filename and file.mimetype in allowed_types:
                    result = cloudinary_upload(
                        file,
                        folder=f"users/{user['_id']}/documents",
                        resource_type="auto"
                    )
                    if result:
                        update_fields["documents"].append({
                            "public_id": result["public_id"],
                            "url": result["secure_url"],
                            "document_type": get_document_type(file, i),
                            "uploaded_at": datetime.now(timezone.utc),
                            "verified": False
                        })

            users_collection.update_one({"email": email}, {"$set": update_fields})
            user_data = users_collection.find_one({"email": email})

        else:
            # New user
            user_id = str(uuid.uuid4())
            user_data = {
                "_id": user_id,
                "first_name": data.get("first_name"),
                "middle_name": data.get("middle_name", ""),
                "last_name": data.get("last_name"),
                "email": email,
                "phone": data.get("phone"),
                "password": hash_password(data.get("password")),
                "department": data.get("department"),
                "commune": data.get("commune"),
                "address": data.get("address"),
                "status": "pending_verification",
                "verification_status": "unverified",
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
                "documents": [],
                "face_image": {},
                "loan_limit": 100000
            }

            # Handle face image upload
            if "face_image" in files:
                file = files["face_image"]
                if file.filename:
                    result = cloudinary_upload(
                        file,
                        folder=f"users/{user_id}/verification",
                        public_id="face_image",
                        overwrite=True,
                        resource_type="image"
                    )
                    if result and result.get("secure_url"):
                        user_data["face_image"] = {
                            "url": result["secure_url"],
                            "uploaded_at": datetime.now(timezone.utc)
                        }

            # Handle document uploads
            doc_files = files.getlist("document[]") or files.getlist("document") or []
            if "proof_of_address" in files:
                doc_files.append(files["proof_of_address"])

            for i, file in enumerate(doc_files):
                if file and file.filename and file.mimetype in allowed_types:
                    result = cloudinary_upload(
                        file,
                        folder=f"users/{user_id}/documents",
                        resource_type="auto"
                    )
                    if result:
                        user_data["documents"].append({
                            "public_id": result["public_id"],
                            "url": result["secure_url"],
                            "document_type": get_document_type(file, i),
                            "uploaded_at": datetime.now(timezone.utc),
                            "verified": False
                        })

            users_collection.insert_one(user_data)

        # Return user data
        response_data = {
            "message": "User registered successfully",
            "user": {
                "_id": user_data["_id"],
                "first_name": user_data.get("first_name"),
                "middle_name": user_data.get("middle_name"),
                "last_name": user_data.get("last_name"),
                "email": user_data.get("email"),
                "phone": user_data.get("phone"),
                "department": user_data.get("department"),
                "commune": user_data.get("commune"),
                "address": user_data.get("address"),
                "status": user_data.get("status"),
                "verification_status": user_data.get("verification_status"),
                "loan_limit": user_data.get("loan_limit"),
                "documents": user_data.get("documents", []),
                "face_image": user_data.get("face_image")
            }
        }

        return jsonify(response_data), 201

    except Exception as e:
        app.logger.exception("Registration error")
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route("/api/check-user", methods=["POST"])
def check_user():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    phone = data.get("phone", "").strip()

    result = {
        "email_s": False,
        "email_verified": False,
        "phone_s": False
    }

    if email:
        user = users_collection.find_one({"email": email})
        if user:
            result["email_s"] = True
            result["email_verified"] = user.get("verification_status") == "verified"

    if phone:
        if users_collection.find_one({"phone": phone}):
            result["phone_s"] = True

    return jsonify(result), 200

import random
from datetime import datetime, timezone, timedelta
from flask import request, jsonify

# --- Verify Email ---
from flask import request, jsonify
from datetime import datetime, timezone
from datetime import datetime, timezone, timedelta
import random
from flask import Flask, request, jsonify

# --- Verify Email Endpoint ---
@app.route("/api/verify-email", methods=["POST"])
def verify_email():
    try:
        data = request.get_json()
        if not data or "email" not in data or "verification_code" not in data:
            return jsonify({'error': 'Email and verification code are required'}), 400

        email = data["email"].strip().lower()
        code = data["verification_code"].strip()

        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        stored_code = user.get("verification_code")
        expires = user.get("verification_code_expires")

        if not stored_code or not expires:
            return jsonify({'error': 'No verification code found'}), 400

        # Ensure expires is timezone-aware
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

        # Check if code expired
        if datetime.now(timezone.utc) > expires:
            return jsonify({'error': 'Verification code expired'}), 400

        # Validate code
        if code != stored_code:
            return jsonify({'error': 'Invalid verification code'}), 400

        # --- Mark user as verified and all documents/face_image ---
        updated_documents = []
        for doc in user.get("documents", []):
            doc["verified"] = True
            updated_documents.append(doc)

        face_image = user.get("face_image", {})
        if face_image:
            face_image["verified"] = True

        users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "status": "verified",
                    "verification_status": "verified",
                    "documents": updated_documents,
                    "face_image": face_image,
                    "updated_at": datetime.now(timezone.utc)
                },
                "$unset": {"verification_code": "", "verification_code_expires": ""}
            }
        )

        return jsonify({'success': True, 'message': 'Email verified successfully and all documents marked verified'}), 200

    except Exception as e:
        app.logger.error(f"Verify email error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Bad internet connection'}), 500

# --- Resend Verification Code Endpoint ---
@app.route('/api/resend-verification-code', methods=['POST'])
def resend_verification_code():
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'error': 'Email is required'}), 400

        email = data['email'].strip().lower()
        user = users_collection.find_one({'email': email})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Generate new 6-digit verification code
        verification_code = ''.join(random.choices('0123456789', k=6))
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)

        # Update user with new code
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'verification_code': verification_code,
                      'verification_code_expires': expires}}
        )

        # Send the verification code via email
        send_verification_email(user['email'], user['first_name'], verification_code)

        return jsonify({'success': True, 'message': 'Verification code resent'}), 200

    except Exception as e:
        app.logger.error(f"Resend verification code error: {str(e)}", exc_info=True)
        return jsonify({'error': 'Bad internet connection'}), 500


@app.route('/api/login', methods=['POST'])
def login():
    """User login endpoint"""
    data = request.get_json()
    
    # Validate required fields
    if not data or ('email' not in data and 'phone' not in data) or 'password' not in data:
        return jsonify({'error': 'Please provide either email or phone and password'}), 400
    
    # Find user by email or phone
    query = {'email': data['email']} if 'email' in data else {'phone': data['phone']}
    user = users_collection.find_one(query)
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Verify password
    if not check_password(data['password'], user['password']):
        return jsonify({'ferror': 'Invalid credentials'}), 401
    
    # Update last login time
    users_collection.update_one(
        {'_id': user['_id']},
        {'$set': {'last_login': datetime.now(timezone.utc)}}
    )
    
    # Generate and return JWT token
    token = generate_jwt_token(user['_id'])
    
    return jsonify({
        'success': True,
        'token': token,
        'user': {
            'id': str(user['_id']),
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'email': user['email'],
            'phone': user['phone']
        }
    })
# Get full profile
@app.route("/api/profile", methods=["GET"])
@token_required
def get_profile(current_user):
    try:
        profile_data = {
            "id": current_user["_id"],
            "first_name": current_user.get("first_name", ""),
            "middle_name": current_user.get("middle_name", ""),
            "last_name": current_user.get("last_name", ""),
            "email": current_user.get("email", ""),
            "phone": current_user.get("phone", ""),
            "loan_limit": current_user.get("loan_limit", 100000),
            "status": current_user.get("status", ""),
            "face_image": current_user.get("face_image", {}).get("url") if current_user.get("face_image") else None,
            "documents": current_user.get("documents", [])
        }
        return jsonify(user=profile_data), 200
    except Exception as e:
        return jsonify(error="Bad internet connection"), 500



@app.route("/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    """Delete user and cascade related records"""
    try:
        query_id = _to_objectid_or_raw(user_id)
        user = users_col.find_one({"_id": query_id})
        if not user:
            return _error("User not found", 404)

        matches = [{"userId": user_id}]
        try:
            matches.append({"userId": ObjectId(user_id)})
        except Exception:
            pass

        loans_col.delete_many({"$or": matches})
        repayments_col.delete_many({"$or": matches})
        withdrawals_col.delete_many({"$or": matches})

        users_col.delete_one({"_id": query_id})
        return jsonify({"message": "User and related records deleted"}), 200
    except Exception as exc:
        current_app.logger.exception("delete_user error")
        return _error("Bad internet connection", 500)
# Update phone number
@app.route("/api/profile/phone", methods=["PUT"])
@token_required
def update_phone(current_user):
    data = request.get_json()
    if not data or "phone" not in data:
        return jsonify(error="Phone number is required"), 400

    new_phone = data["phone"].strip()
    if not re.match(r'^\+?\d{10,15}$', new_phone):
        return jsonify(error="Invalid phone number format"), 400

    # Check uniqueness
    if users_collection.find_one({"phone": new_phone, "_id": {"$ne": current_user["_id"]}}):
        return jsonify(error="Phone number already in use"), 409

    users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"phone": new_phone, "updated_at": datetime.now(timezone.utc)}}
    )
    return jsonify(success=True, phone=new_phone), 200

# Change password
@app.route("/api/profile/password", methods=["PUT"])
@token_required
def change_password(current_user):
    data = request.get_json()
    if not data or "old_password" not in data or "new_password" not in data:
        return jsonify(error="Both old and new passwords are required"), 400

    old_password = data["old_password"]
    new_password = data["new_password"]

    if not bcrypt.checkpw(old_password.encode(), current_user["password"].encode()):
        return jsonify(error="Old password is incorrect"), 401
    if len(new_password) < 8:
        return jsonify(error="New password must be at least 8 characters"), 400

    hashed_pw = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$set": {"password": hashed_pw, "updated_at": datetime.now(timezone.utc)}}
    )
    return jsonify(success=True, message="Password updated successfully"), 200

# List documents
@app.route("/api/profile/documents", methods=["GET"])
@token_required
def list_documents(current_user):
    documents = current_user.get("documents", [])
    return jsonify(documents=documents), 200

# Upload new document
@app.route("/api/profile/documents", methods=["POST"])
@token_required
def upload_document(current_user):
    if "document" not in request.files:
        return jsonify(error="Document file is required"), 400

    file = request.files["document"]
    if file.mimetype not in ALLOWED_DOC_TYPES:
        return jsonify(error="Invalid document type"), 400
    if file.content_length > MAX_DOC_SIZE:
        return jsonify(error="Document exceeds 5MB size limit"), 400

    folder = f"users/{current_user['_id']}/documents"
    result = cloudinary_upload(
        file,
        folder=folder,
        resource_type="auto",
        tags=["user_document"]
    )

    new_doc = {
        "public_id": result["public_id"],
        "url": result["secure_url"],
        "document_type": request.form.get("document_type", "unknown"),
        "uploaded_at": datetime.now(timezone.utc),
        "verified": False
    }

    users_collection.update_one(
        {"_id": current_user["_id"]},
        {"$push": {"documents": new_doc}, "$set": {"updated_at": datetime.now(timezone.utc)}}
    )

    return jsonify(success=True, document=new_doc), 201



from functools import wraps
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from flask import request, jsonify
import jwt
import os

# Backdoor verification endpoint
@app.route('/api/verify-backdoor', methods=['POST'])
def verify_backdoor():
    try:
        data = request.get_json()
        if not data or 'code' not in data:
            return jsonify({"valid": False}), 400

        # Your secret backdoor codes (change these!)
        valid_codes = ["D45192091425Ea@", "KREDINOU_EMERGENCY"]  
        
        # Constant-time comparison to prevent timing attacks
        is_valid = any(hmac.compare_digest(data['code'].strip(), code) for code in valid_codes)
        
        if is_valid:
            # Create emergency session token (valid for 1 hour)
            token = jwt.encode({
                "backdoor_access": True,
                "exp": datetime.now(timezone.utc) + timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            return jsonify({
                "valid": True,
                "token": token
            })
        
        return jsonify({"valid": False}), 403
        
    except Exception as e:
        print(f"Backdoor verification error: {str(e)}")
        return jsonify({"valid": False}), 500

# Protected admin endpoint
@app.route('/api/system/emergency-admin', methods=['POST'])
def emergency_admin():
    """Endpoint for emergency admin actions"""
    try:
        # Verify JWT token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Unauthorized"}), 401
            
        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            if not payload.get("backdoor_access"):
                return jsonify({"error": "Invalid token scope"}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        
        # Process admin action
        data = request.get_json()
        action = data.get('action')
        
        if action == "create_session":
            user_id = data.get('user_id')
            if not user_id:
                return jsonify({"error": "Missing user_id"}), 400
                
            # Create admin session logic here
            return jsonify({"success": True, "user_id": user_id})
            
        return jsonify({"error": "Invalid action"}), 400
        
    except Exception as e:
        app.logger.error(f"Emergency admin error: {str(e)}", exc_info=True)
        return jsonify({"error": "Bad internet connection"}), 500

    return jsonify({"success": True}), 200


@app.route("/api/send-otp", methods=["POST"])
def send_otp_pre_registration():
    try:
        data = request.get_json()
        first_name = data.get("first_name", "").strip()
        email = data.get("email", "").strip().lower()
        phone = data.get("phone", "").strip()

        if not first_name or not email or not phone:
            return jsonify({"success": False, "message": "First name, email, and phone are required"}), 400

        # Generate OTP
        verification_code = ''.join(random.choices(string.digits, k=6))
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)

        # Upsert user with pending status if not s
        user = users_collection.find_one({"email": email})
        if not user:
            user_id = str(uuid.uuid4())
            users_collection.insert_one({
                "_id": user_id,
                "first_name": first_name,
                "email": email,
                "phone": phone,
                "status": "pending_verification",
                "verification_code": verification_code,
                "verification_code_expires": expires,
                "created_at": datetime.now(timezone.utc)
            })
        else:
            # Update OTP for ing pending user
            users_collection.update_one(
                {"email": email},
                {"$set": {
                    "verification_code": verification_code,
                    "verification_code_expires": expires,
                    "first_name": first_name,
                    "phone": phone,
                    "status": "pending_verification"
                }}
            )

        # Send email with OTP
        send_verification_email(email, first_name, verification_code)

        return jsonify({"success": True, "message": "OTP sent successfully"}), 200

    except Exception as e:
        app.logger.error(f"Error sending pre-registration OTP: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Bad internet connection"}), 500

@app.route("/api/verify-otp", methods=["POST"])
def verify_otp_pre_registration():
    try:
        data = request.get_json()
        email = data.get("email", "").strip().lower()
        otp_code = data.get("otp_code", "").strip()

        if not email or not otp_code:
            return jsonify({"success": False, "message": "Email and OTP are required"}), 400

        user = users_collection.find_one({"email": email})
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        expires = user.get("verification_code_expires")
        if expires is None:
            expires = datetime.now(timezone.utc)
        elif expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

        if datetime.now(timezone.utc) > expires:
            return jsonify({"success": False, "message": "OTP expired"}), 400

        if otp_code != user.get("verification_code"):
            return jsonify({"success": False, "message": "Invalid OTP"}), 400

        users_collection.update_one(
            {"email": email},
            {"$set": {"status": "verified"},
             "$unset": {"verification_code": "", "verification_code_expires": ""}}
        )

        return jsonify({"success": True, "message": "OTP verified. You can continue registration."}), 200

    except Exception as e:
        app.logger.error(f"Error verifying OTP: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Bad internet connection"}), 500




app.register_blueprint(loans_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(repayments_bp, url_prefix="/repayments")
app.register_blueprint(admin_repayments_bp, url_prefix="/admin")
app.register_blueprint(wallet_bp, url_prefix="/wallets", strict_slashes=False)
app.register_blueprint(users_bp)
app.register_blueprint(manager_bp, url_prefix="/admin") 
app.register_blueprint(acct_bp)
app.register_blueprint(contact_bp)
app.register_blueprint(user_dashboard_bp)
app.register_blueprint(reset_password_bp)
app.register_blueprint(messages_bp, url_prefix="/messages") 
















@app.route("/api/profileee/", methods=["GET"])
@token_required
def get_profileee(current_user):
    print("Current user ID:", current_user["_id"])
    print("Documents:", current_user.get("documents"))
    profile = {
        "_id": current_user["_id"],
        "first_name": current_user.get("first_name"),
        "middle_name": current_user.get("middle_name"),
        "last_name": current_user.get("last_name"),
        "email": current_user.get("email"),
        "phone": current_user.get("phone"),
        "department": current_user.get("department"),
        "commune": current_user.get("commune"),
        "address": current_user.get("address"),
        "loan_limit": current_user.get("loan_limit", 0),
        "face_image": current_user.get("face_image"),
        "documents": current_user.get("documents", [])
    }
    return jsonify(profile), 200


@app.route("/api/profileee/", methods=["PATCH"])
@token_required
def update_login_info(current_user):
    try:
        data = request.get_json()
        if not data:
            return jsonify(error="Invalid or missing JSON body"), 400

        update_fields = {}
        if "email" in data:
            update_fields["email"] = data["email"].strip()
        if "phone" in data:
            update_fields["phone"] = data["phone"].strip()
        if "password" in data and data["password"]:
            update_fields["password"] = generate_password_hash(str(data["password"]))

        if not update_fields:
            return jsonify(message="No fields to update"), 400

        update_fields["updated_at"] = datetime.now(timezone.utc)

        # Make sure _id type matches MongoDB
        _id = current_user["_id"]
        try:
            users_collection.update_one({"_id": _id}, {"$set": update_fields})
        except Exception as e:
            app.logger.error(f"DB update failed for user {_id}: {str(e)}")
            return jsonify(error=f"Database update failed: {str(e)}"), 500

        return jsonify(success=True, message="Login info updated"), 200

    except Exception as e:
        app.logger.exception("Unexpected error in update_login_info")
        return jsonify(error="Bad internet connection"), 500

# -------------------------
# ACTIVE LOAN ROUTE
# -------------------------

@app.route("/api/loans/activee", methods=["GET"])
@token_required
def get_active_loan(current_user):
    loan = loans_collection.find_one({"user_id": current_user["_id"], "status": "active"})
    if loan:
        # Convert dates to ISO format for frontend
        loan["_id"] = str(loan["_id"])
        if "applicationDate" in loan:
            loan["applicationDate"] = {"$date": loan["applicationDate"].isoformat()}
        if "dueDate" in loan:
            loan["dueDate"] = {"$date": loan["dueDate"].isoformat()}
        return jsonify(loan), 200
    return jsonify(message="No active loan found"), 404
import os
def get_banner():
    banner = r"""
         KrediNou Server v.1 by Destiny Tch
"""
    return {
        "banner": banner,
        "host": "0.0.0.0",
        "port": 5000,
        "debug": os.getenv("FLASK_DEBUG", True),
        "status": "All blueprints registered successfully ✅"
    }

@app.route("/", methods=["GET"])
def root():
    return jsonify(get_banner()), 200

if __name__ == "__main__":
    info = get_banner()
    print(info["banner"])
    print("="*50)
    print(f"Host: {info['host']} | Port: {info['port']} | Debug: {info['debug']}")
    print(info["status"])
    print("="*50)

    app.run()




