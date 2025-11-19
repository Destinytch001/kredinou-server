from flask import Blueprint, request, jsonify
from flask_cors import CORS
from datetime import datetime
from bson import ObjectId
from extensions import get_db
import cloudinary
import cloudinary.uploader
import uuid
import os

# -----------------------------
# Blueprint
# -----------------------------
acct_bp = Blueprint("acct", __name__)

# -----------------------------
# CORS config for this blueprint
# -----------------------------
CORS(
    acct_bp,
    resources={
        r"/*": {
            "origins": [
                "http://localhost:8000",
                "http://127.0.0.1:8000",
                "https://kredinou.com",
                "https://www.kredinou.com",
                "https://destinytch.com.ng",
                "https://www.destinytch.com.ng"
            ]
        }
    },
    supports_credentials=True
)

# -----------------------------
# Cloudinary configuration (HARDCODED)
# -----------------------------
cloudinary.config(
    cloud_name="dtgtadxgq",
    api_key="725813336421935",
    api_secret="ZAEcNd5qQ2KGtgbSTrlMscm9cnA",
    secure=True
)

# -----------------------------
# Mongo collections
# -----------------------------
db = get_db()
payment_methods_collection = db.payment_methods

# -----------------------------
# Helper: Upload file to Cloudinary
# -----------------------------
def cloudinary_upload(file_obj, folder="payment_methods", public_id=None):
    """
    Uploads a file object to Cloudinary and returns the result dict.
    """
    if not public_id:
        public_id = str(uuid.uuid4())
    try:
        result = cloudinary.uploader.upload(
            file_obj,
            folder=folder,
            public_id=public_id,
            overwrite=True,
            resource_type="image"
        )
        return result
    except Exception as e:
        print(f"Cloudinary upload error: {str(e)}")
        raise e

# -----------------------------
# Get Payment Method Details
# -----------------------------
@acct_bp.route("/<method_type>/<detail_type>", methods=["GET"])
def get_payment_details(method_type, detail_type):
    """
    Get payment method details or QR code
    method_type: 'moncash' or 'natcash'
    detail_type: 'transfer-details' or 'qr-code'
    """
    try:
        print(f"Getting {method_type} {detail_type}")
        
        # Find the payment method document
        payment_method = payment_methods_collection.find_one({
            "method_type": method_type,
            "is_active": True
        })
        
        if not payment_method:
            return jsonify({"error": f"{method_type} payment method not found"}), 404
        
        # Return appropriate data based on request type
        if detail_type == "transfer-details":
            response_data = {
                "accountName": payment_method.get("account_name", ""),
                "accountNumber": payment_method.get("account_number", ""),
                "instructions": payment_method.get("instructions", "")
            }
            print(f"Returning transfer details: {response_data}")
            return jsonify(response_data)
        
        elif detail_type == "qr-code":
            qr_url = payment_method.get("qr_code_url")
            if not qr_url:
                return jsonify({"error": "QR code not available"}), 404
            print(f"Returning QR code URL: {qr_url}")
            return jsonify({"qrCodeUrl": qr_url})
        
        else:
            return jsonify({"error": "Invalid detail type"}), 400
            
    except Exception as e:
        print(f"Error in get_payment_details: {str(e)}")
        return jsonify({"error": str(e)}), 500

# -----------------------------
# Admin: Update Payment Method Details
# -----------------------------
@acct_bp.route("/admin/<method_type>/details", methods=["POST"])
def update_payment_details(method_type):
    """
    Update payment method details (account name, number, instructions)
    """
    try:
        print(f"Updating {method_type} details")
        
        # Check if request has JSON data
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
            
        data = request.get_json()
        print(f"Received data: {data}")
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Update or create the payment method document
        update_data = {
            "method_type": method_type,
            "account_name": data.get("accountName", ""),
            "account_number": data.get("accountNumber", ""),
            "instructions": data.get("instructions", ""),
            "is_active": data.get("isActive", True),
            "updated_at": datetime.utcnow()
        }
        
        # Set created_at if creating new document
        result = payment_methods_collection.update_one(
            {"method_type": method_type},
            {"$set": update_data, 
             "$setOnInsert": {"created_at": datetime.utcnow()}},
            upsert=True
        )
        
        print(f"Database update result: {result.modified_count} modified, {result.upserted_id} upserted")
        
        return jsonify({
            "message": f"{method_type} details updated successfully",
            "modified": result.modified_count > 0,
            "upserted": result.upserted_id is not None
        })
        
    except Exception as e:
        print(f"Error in update_payment_details: {str(e)}")
        return jsonify({"error": str(e)}), 500

# -----------------------------
# Admin: Upload QR Code
# -----------------------------
@acct_bp.route("/admin/<method_type>/qr-code", methods=["POST"])
def upload_qr_code(method_type):
    """
    Upload QR code for a payment method
    """
    try:
        print(f"Uploading QR code for {method_type}")
        
        if 'qrFile' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        qr_file = request.files['qrFile']
        if qr_file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        print(f"Received file: {qr_file.filename}")
        
        # Upload to Cloudinary
        result = cloudinary_upload(
            qr_file, 
            folder="payment_qr_codes", 
            public_id=f"{method_type}_qr"
        )
        qr_url = result.get("secure_url")
        print(f"Uploaded to Cloudinary: {qr_url}")
        
        # Update the payment method document with QR code URL
        update_result = payment_methods_collection.update_one(
            {"method_type": method_type},
            {"$set": {
                "qr_code_url": qr_url,
                "updated_at": datetime.utcnow()
            }, "$setOnInsert": {
                "is_active": True,
                "created_at": datetime.utcnow(),
                "account_name": "",
                "account_number": "",
                "instructions": ""
            }},
            upsert=True
        )
        
        print(f"Database QR update result: {update_result.modified_count} modified")
        
        return jsonify({
            "message": f"{method_type} QR code uploaded successfully",
            "qrCodeUrl": qr_url
        })
        
    except Exception as e:
        print(f"Error in upload_qr_code: {str(e)}")
        return jsonify({"error": str(e)}), 500

# -----------------------------
# Admin: Get All Payment Methods
# -----------------------------
@acct_bp.route("/admin/methods", methods=["GET"])
def get_all_payment_methods():
    """
    Get all payment methods (admin view)
    """
    try:
        print("Fetching all payment methods")
        methods = list(payment_methods_collection.find({}))
        print(f"Found {len(methods)} methods")
        
        # Convert ObjectId to string for JSON serialization
        for method in methods:
            method["_id"] = str(method["_id"])
            # Convert datetime objects to ISO format strings
            for field in ["created_at", "updated_at"]:
                if field in method and isinstance(method[field], datetime):
                    method[field] = method[field].isoformat()
        
        return jsonify(methods)
        
    except Exception as e:
        print(f"Error in get_all_payment_methods: {str(e)}")
        return jsonify({"error": str(e)}), 500

# -----------------------------
# Admin: Toggle Payment Method Status
# -----------------------------
@acct_bp.route("/admin/<method_type>/toggle", methods=["POST"])
def toggle_payment_method(method_type):
    """
    Enable/disable a payment method
    """
    try:
        print(f"Toggling {method_type} status")
        
        payment_method = payment_methods_collection.find_one({"method_type": method_type})
        
        if not payment_method:
            return jsonify({"error": f"{method_type} payment method not found"}), 404
        
        new_status = not payment_method.get("is_active", True)
        
        result = payment_methods_collection.update_one(
            {"method_type": method_type},
            {"$set": {
                "is_active": new_status,
                "updated_at": datetime.utcnow()
            }}
        )
        
        status = "enabled" if new_status else "disabled"
        return jsonify({
            "message": f"{method_type} payment method {status}",
            "modified": result.modified_count > 0
        })
        
    except Exception as e:
        print(f"Error in toggle_payment_method: {str(e)}")
        return jsonify({"error": str(e)}), 500


# -----------------------------
# Health Check Endpoint
# -----------------------------
@acct_bp.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        payment_methods_collection.find_one()
        return jsonify({"status": "healthy", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500
