from flask import Blueprint, request, jsonify
from flask_cors import CORS
from datetime import datetime
from bson import ObjectId
from extensions import get_db

# -----------------------------
# Blueprint
# -----------------------------
wallet_bp = Blueprint("wallet", __name__)

# -----------------------------



# CORS config for this blueprint
# -----------------------------
CORS(
    wallet_bp,
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
import cloudinary
import cloudinary.uploader
import uuid
import os

# -----------------------------
# Cloudinary configuration
# -----------------------------
cloudinary.config(
    cloud_name="dtgtadxgq",
    api_key="725813336421935",
    api_secret="ZAEcNd5qQ2KGtgbSTrlMscm9cnA",
    secure=True
)
import requests

BREVO_API_KEY = "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"
BREVO_SENDER_EMAIL = "support@kredinou.com"
BREVO_SENDER_NAME = "KrediNou"

def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Send an email via Brevo API (HTML content).
    Returns True if sent successfully, False otherwise.
    """
    payload = {
        "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": body
    }
    headers = {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json"
    }

    try:
        response = requests.post("https://api.brevo.com/v3/smtp/email", json=payload, headers=headers)
        if response.status_code in [200, 201, 202]:
            print(f"✅ Email sent to {to_email}")
            return True
        else:
            print(f"❌ Failed to send email: {response.status_code}, {response.text}")
            return False
    except Exception as e:
        print(f"❌ Exception sending email: {e}")
        return False

# -----------------------------
# Helper: Upload file to Cloudinary
# -----------------------------
def cloudinary_upload(file_obj, folder="default_folder", public_id=None):
    """
    Uploads a file object to Cloudinary and returns the result dict.
    """
    if not public_id:
        public_id = str(uuid.uuid4())
    result = cloudinary.uploader.upload(
        file_obj,
        folder=folder,
        public_id=public_id,
        overwrite=True,
        resource_type="image"
    )
    return result

# -----------------------------
# Mongo collections
# -----------------------------
db = get_db()
wallets_collection = db.wallets
withdrawals_collection = db.withdrawals
loans_collection = db.loans
users_collection = db.users
import uuid

# -----------------------------
# Utility: Sync wallets for all completed loans
# -----------------------------
def sync_wallet(user_id):
    loans = list(loans_collection.find({"userId": user_id, "disbursementStatus": "completed"}))
    if not loans:
        return [], 0  # No completed loans

    # Get user details for walletId generation
    user = users_collection.find_one({"_id": user_id})
    first = (user.get("first_name", "") if user else "USER").strip().capitalize()
    last = (user.get("last_name", "") if user else "").strip().capitalize()

    wallets = []
    total_balance = 0

    for loan in loans:
        wallet = wallets_collection.find_one({"userId": user_id, "loanId": loan["_id"]})

        if not wallet:
            # Generate walletId
            unique_suffix = uuid.uuid4().hex[:4].upper()
            wallet_id = f"KRD-{first}{last[:1]}-{unique_suffix}"

            # Create wallet if it doesn't exist
            wallet_data = {
                "userId": user_id,
                "loanId": loan["_id"],
                "walletId": wallet_id,
                "balance": loan.get("amount", 0),  # default 0 if missing
                "currency": loan.get("currency", "HTG"),
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow(),
            }
            wallets_collection.insert_one(wallet_data)
            balance = wallet_data["balance"]

        else:
            # If wallet exists but has no walletId, generate and update it
            if "walletId" not in wallet or not wallet["walletId"]:
                unique_suffix = uuid.uuid4().hex[:4].upper()
                wallet_id = f"KRD-{first}{last[:1]}-{unique_suffix}"
                wallets_collection.update_one(
                    {"_id": wallet["_id"]},
                    {"$set": {"walletId": wallet_id, "updatedAt": datetime.utcnow()}}
                )

            balance = wallet.get("balance", 0)

        total_balance += balance
        wallets.append({
            "loanId": str(loan["_id"]),
            "balance": balance,
            "currency": loan.get("currency", "HTG")
        })

    return wallets, total_balance



@wallet_bp.route("/", methods=["GET", "OPTIONS"])
def get_wallet():
    if request.method == "OPTIONS":
        return '', 200  # allow preflight

    user_id = request.args.get("userId")
    if not user_id:
        return jsonify({"error": "userId is required"}), 400

    wallets, total_balance = sync_wallet(user_id)
    loan_ids = [w["loanId"][:8] + "..." for w in wallets]  # trimmed IDs

    return jsonify({
        "balance": total_balance,  # always a number
        "loanIds": loan_ids
    })
from flask import request, jsonify
from datetime import datetime
import uuid
import requests

# Brevo (Sendinblue) API configuration
BREVO_API_KEY = "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"
BREVO_SENDER_EMAIL = "support@kredinou.com"
BREVO_SENDER_NAME = "KrediNou"
ADMIN_EMAIL = "support@kredinou.com"

def send_admin_email(amount, service, account_name, account_number, qr_url, deducted_per_wallet):
    subject = "New Withdrawal Request"
    body = f"""
    <p>New withdrawal request received:</p>
    <ul>
        <li><b>Amount:</b> {amount}</li>
        <li><b>Service:</b> {service}</li>
        <li><b>Account Name:</b> {account_name or 'N/A'}</li>
        <li><b>Account Number:</b> {account_number or 'N/A'}</li>
        <li><b>QR URL:</b> {qr_url or 'N/A'}</li>
        <li><b>Wallet Deductions:</b> {deducted_per_wallet}</li>
    </ul>
    """
    payload = {
        "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
        "to": [{"email": ADMIN_EMAIL}],
        "subject": subject,
        "htmlContent": body
    }
    headers = {"api-key": BREVO_API_KEY, "Content-Type": "application/json"}

    try:
        response = requests.post("https://api.brevo.com/v3/smtp/email", json=payload, headers=headers)
        if response.status_code in [200, 201, 202]:
            print("✅ Admin notified for withdrawal")
            return True
        else:
            print(f"❌ Failed to notify admin: {response.status_code}, {response.text}")
            return False
    except Exception as e:
        print(f"❌ Exception sending admin email: {e}")
        return False


@wallet_bp.route("/withdraw", methods=["POST", "OPTIONS"])
def make_withdrawal():
    if request.method == "OPTIONS":
        return '', 200

    # Detect JSON vs form-data
    if request.content_type.startswith("application/json"):
        data = request.get_json()
        user_id = data.get("userId")
        amount = data.get("amount")
        account_name = data.get("accountName")
        account_number = data.get("accountNumber")
        service = data.get("service")
        qr_file = None
    else:
        user_id = request.form.get("userId")
        amount = request.form.get("amount")
        service = request.form.get("service")
        qr_file = request.files.get("qrFile")
        account_name = None
        account_number = None

    if not all([user_id, amount, service]):
        return jsonify({"error": "userId, amount, and service are required"}), 400

    try:
        amount = float(amount)
        if amount <= 0:
            return jsonify({"error": "Amount must be greater than 0"}), 400
    except ValueError:
        return jsonify({"error": "Amount must be a number"}), 400

    wallets = list(wallets_collection.find({"userId": user_id}))
    if not wallets:
        return jsonify({"error": "No wallet found"}), 400

    total_balance = sum(w.get("balance", 0) for w in wallets)
    if amount > total_balance:
        return jsonify({"error": f"Amount exceeds total wallet balance ({total_balance})"}), 400

    remaining_amount = amount
    deducted_per_wallet = {}

    for wallet in wallets:
        w_balance = wallet.get("balance", 0)
        if w_balance >= remaining_amount:
            new_balance = w_balance - remaining_amount
            wallets_collection.update_one(
                {"_id": wallet["_id"]},
                {"$set": {"balance": new_balance, "updatedAt": datetime.utcnow()}}
            )
            deducted_per_wallet[str(wallet["_id"])] = remaining_amount
            remaining_amount = 0
            break
        else:
            wallets_collection.update_one(
                {"_id": wallet["_id"]},
                {"$set": {"balance": 0, "updatedAt": datetime.utcnow()}}
            )
            deducted_per_wallet[str(wallet["_id"])] = w_balance
            remaining_amount -= w_balance

    qr_url = None
    if qr_file:
        try:
            result = cloudinary_upload(qr_file, folder="withdrawals_qr", public_id=str(uuid.uuid4()))
            qr_url = result.get("secure_url")
        except Exception as e:
            return jsonify({"error": f"QR upload failed: {str(e)}"}), 500

    withdrawal = {
        "userId": user_id,
        "walletDeductions": deducted_per_wallet,
        "amount": amount,
        "accountName": account_name,
        "accountNumber": account_number,
        "service": service,
        "qrUrl": qr_url,
        "status": "pending",
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow()
    }
    result = withdrawals_collection.insert_one(withdrawal)
    total_balance_after = sum(w.get("balance", 0) for w in wallets_collection.find({"userId": user_id}))

    # Send admin email via Brevo API
    send_admin_email(amount, service, account_name, account_number, qr_url, deducted_per_wallet)

    return jsonify({
        "message": "Withdrawal request submitted successfully",
        "withdrawalId": str(result.inserted_id),
        "newBalance": total_balance_after,
        "qrUrl": qr_url
    }), 201

# -----------------------------
# Route: User withdrawal history
# -----------------------------
@wallet_bp.route("/withdrawals", methods=["GET"])
def withdrawal_history():
    user_id = request.args.get("userId")
    if not user_id:
        return jsonify({"error": "userId is required"}), 400

    try:
        withdrawals = withdrawals_collection.find({"userId": user_id}).sort("createdAt", -1)
        history = []
        for w in withdrawals:
            created_at = w.get("createdAt")
            loan_ids_display = [lid[:8] + "..." for lid in w.get("loanIds", [])]  # trim loan IDs
            history.append({
                "withdrawalId": str(w["_id"]),
                "loanIds": loan_ids_display,
                "amount": w.get("amount"),
                "accountName": w.get("accountName"),
                "accountNumber": w.get("accountNumber"),
                "service": w.get("service"),
                "status": w.get("status"),
                "createdAt": created_at.isoformat() if created_at else None
            })
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
# -----------------------------
# Admin Routes (Open, no auth)
# -----------------------------
@wallet_bp.route("/admin/withdrawals", methods=["GET", "OPTIONS"])
def admin_get_withdrawals():
    if request.method == "OPTIONS":
        return '', 200

    try:
        withdrawals = list(withdrawals_collection.find().sort("createdAt", -1))
        all_requests = []

        for w in withdrawals:
            created_at = w.get("createdAt")
            full_name = "N/A"
            loan_ids = []

            # Map wallet IDs to loans
            wallet_ids = list(w.get("walletDeductions", {}).keys())
            for wid in wallet_ids:
                wallet = wallets_collection.find_one({"_id": ObjectId(wid)})
                if wallet:
                    loan = loans_collection.find_one({"_id": wallet["loanId"]})
                    if loan:
                        loan_ids.append(str(loan["_id"])[:8] + "...")
                        if "user" in loan and "fullName" in loan["user"]:
                            full_name = loan["user"]["fullName"]

            all_requests.append({
                "withdrawalId": str(w["_id"]),
                "userId": str(w.get("userId")),
                "userFullName": full_name,
                "loanIds": loan_ids,
                "amount": w.get("amount"),
                "accountName": w.get("accountName"),
                "accountNumber": w.get("accountNumber"),
                "service": w.get("service"),
                "status": w.get("status"),
                "createdAt": created_at.isoformat() if created_at else None,
                "qrUrl": w.get("qrUrl")  # <-- Include QR Cloudinary URL if exists
            })

        return jsonify(all_requests)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


from flask import request, jsonify
from datetime import datetime
from bson import ObjectId
import traceback
import requests

# Brevo API config
BREVO_API_KEY = "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"
BREVO_SENDER_EMAIL = "support@kredinou.com"
BREVO_SENDER_NAME = "KrediNou"

def send_brevo_email(to_email, subject, body):
    payload = {
        "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": body
    }
    headers = {"api-key": BREVO_API_KEY, "Content-Type": "application/json"}
    try:
        response = requests.post("https://api.brevo.com/v3/smtp/email", json=payload, headers=headers)
        if response.status_code in [200, 201, 202]:
            print(f"✅ Email sent to {to_email}")
            return True
        else:
            print(f"❌ Failed to send email to {to_email}: {response.status_code} {response.text}")
            return False
    except Exception as e:
        print(f"❌ Exception sending email: {e}")
        return False


@wallet_bp.route("/admin/withdrawals/<withdrawal_id>/approve", methods=["POST", "OPTIONS"])
def admin_approve_withdrawal(withdrawal_id):
    if request.method == "OPTIONS":
        return '', 200

    try:
        # Find withdrawal
        withdrawal = withdrawals_collection.find_one({"_id": ObjectId(withdrawal_id)})
        if not withdrawal:
            return jsonify({"error": "Withdrawal not found"}), 404

        # Update status
        withdrawals_collection.update_one(
            {"_id": withdrawal["_id"]},
            {"$set": {"status": "approved", "updatedAt": datetime.utcnow()}}
        )

        # -------------------------
        # Fetch user email and full name
        # -------------------------
        user_email = withdrawal.get("user", {}).get("email")
        first_name = withdrawal.get("user", {}).get("first_name")
        middle_name = withdrawal.get("user", {}).get("middle_name")
        last_name = withdrawal.get("user", {}).get("last_name")
        user_name = " ".join(filter(None, [first_name, middle_name, last_name])) if first_name else None

        # fallback: fetch user from users_collection if missing
        if not user_email and "userId" in withdrawal:
            user = users_collection.find_one({"_id": withdrawal["userId"]})
            if user:
                user_email = user.get("email")
                first_name = user.get("first_name")
                middle_name = user.get("middle_name")
                last_name = user.get("last_name")
                user_name = " ".join(filter(None, [first_name, middle_name, last_name]))

        if not user_name:
            user_name = "Customer"

        # -------------------------
        # Send email to user via Brevo
        # -------------------------
        if user_email:
            subject = "Your Withdrawal Has Been Approved ✅"
            body = (
                f"<p>Hello {user_name},</p>"
                f"<p>Your withdrawal request of <b>{withdrawal.get('amount')} HTG</b> "
                f"has been approved and processed successfully.</p>"
                f"<p>The funds will reflect in your wallet immediately.</p>"
                f"<p>Thank you for using KrediNou.</p>"
                f"<p>- The KrediNou Team</p>"
            )
            send_brevo_email(user_email, subject, body)

        return jsonify({"message": "Withdrawal approved"}), 200

    except Exception as e:
        print(f"❌ Error approving withdrawal: {e}")
        traceback.print_exc()
        return jsonify({"error": "Failed to approve withdrawal"}), 500


@wallet_bp.route("/admin/withdrawals/<withdrawal_id>/reject", methods=["POST", "OPTIONS"])
def admin_reject_withdrawal(withdrawal_id):
    if request.method == "OPTIONS":
        return '', 200

    withdrawal = withdrawals_collection.find_one({"_id": ObjectId(withdrawal_id)})
    if not withdrawal:
        return jsonify({"error": "Withdrawal not found"}), 404

    # Restore only the amounts that were actually deducted
    for wallet_id, deducted_amount in withdrawal.get("walletDeductions", {}).items():
        wallet = wallets_collection.find_one({"_id": ObjectId(wallet_id)})
        if wallet:
            new_balance = wallet.get("balance", 0) + deducted_amount
            wallets_collection.update_one(
                {"_id": wallet["_id"]},
                {"$set": {"balance": new_balance, "updatedAt": datetime.utcnow()}}
            )

    withdrawals_collection.update_one(
        {"_id": withdrawal["_id"]},
        {"$set": {"status": "rejected", "updatedAt": datetime.utcnow()}}
    )

    # Recalculate total balance after restoring
    total_balance_after = sum(w.get("balance", 0) for w in wallets_collection.find({"userId": withdrawal.get("userId")}))

    return jsonify({
        "message": "Withdrawal rejected, balance restored",
        "newBalance": total_balance_after
    })

# -----------------------------
# Route: Verify recipient wallet
# -----------------------------
@wallet_bp.route("/verify-wallet", methods=["POST", "OPTIONS"])
def verify_wallet():
    if request.method == "OPTIONS":
        return '', 200

    try:
        data = request.get_json()
        wallet_id = data.get("walletId")
        
        if not wallet_id:
            return jsonify({"error": "walletId is required"}), 400

        # Find wallet by walletId
        wallet = wallets_collection.find_one({"walletId": wallet_id})
        if not wallet:
            return jsonify({"error": "Wallet not found"}), 404

        # Get user details
        user = users_collection.find_one({"_id": wallet["userId"]})
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Prepare response
        user_info = {
            "walletId": wallet_id,
            "name": f"{user.get('first_name', '').strip().capitalize()} {user.get('last_name', '').strip().capitalize()}",
            "userId": str(user["_id"])
        }

        return jsonify({
            "success": True,
            "user": user_info
        }), 200

    except Exception as e:
        print(f"❌ Error verifying wallet: {e}")
        return jsonify({"error": "Internal server error"}), 500

# -----------------------------
# Route: Send money to recipient (FREE - No charges)
# -----------------------------
@wallet_bp.route("/send-money", methods=["POST", "OPTIONS"])
def send_money():
    if request.method == "OPTIONS":
        return '', 200

    try:
        data = request.get_json()
        sender_id = data.get("senderId")
        recipient_wallet_id = data.get("recipientWalletId")
        amount = data.get("amount")
        note = data.get("note", "")

        # Validate input
        if not all([sender_id, recipient_wallet_id, amount]):
            return jsonify({"error": "senderId, recipientWalletId, and amount are required"}), 400

        try:
            amount = float(amount)
            if amount <= 0:
                return jsonify({"error": "Amount must be greater than 0"}), 400
        except ValueError:
            return jsonify({"error": "Amount must be a valid number"}), 400

        # Find recipient wallet
        recipient_wallet = wallets_collection.find_one({"walletId": recipient_wallet_id})
        if not recipient_wallet:
            return jsonify({"error": "Recipient wallet not found"}), 404

        # Check if sender is trying to send to themselves
        if str(recipient_wallet["userId"]) == str(sender_id):
            return jsonify({"error": "Cannot send money to yourself"}), 400

        # Get sender's wallets and calculate total balance
        sender_wallets = list(wallets_collection.find({"userId": sender_id}))
        if not sender_wallets:
            return jsonify({"error": "Sender has no wallets"}), 400

        total_sender_balance = sum(w.get("balance", 0) for w in sender_wallets)
        if amount > total_sender_balance:
            return jsonify({"error": f"Insufficient balance. Available: {total_sender_balance} HTG"}), 400

        # NO FEES - Direct amount transfer
        remaining_deduction = amount
        sender_deductions = {}

        # Deduct from sender's wallets
        for wallet in sender_wallets:
            if remaining_deduction <= 0:
                break

            wallet_balance = wallet.get("balance", 0)
            if wallet_balance >= remaining_deduction:
                new_balance = wallet_balance - remaining_deduction
                wallets_collection.update_one(
                    {"_id": wallet["_id"]},
                    {"$set": {"balance": new_balance, "updatedAt": datetime.utcnow()}}
                )
                sender_deductions[str(wallet["_id"])] = remaining_deduction
                remaining_deduction = 0
            else:
                wallets_collection.update_one(
                    {"_id": wallet["_id"]},
                    {"$set": {"balance": 0, "updatedAt": datetime.utcnow()}}
                )
                sender_deductions[str(wallet["_id"])] = wallet_balance
                remaining_deduction -= wallet_balance

        # Add amount to recipient's wallet
        recipient_new_balance = recipient_wallet.get("balance", 0) + amount
        wallets_collection.update_one(
            {"_id": recipient_wallet["_id"]},
            {"$set": {"balance": recipient_new_balance, "updatedAt": datetime.utcnow()}}
        )

        # Create transaction record
        transaction = {
            "senderId": sender_id,
            "recipientId": recipient_wallet["userId"],
            "recipientWalletId": recipient_wallet_id,
            "amount": amount,
            "fee": 0,
            "totalDeduction": amount,
            "note": note,
            "senderDeductions": sender_deductions,
            "recipientWalletBefore": recipient_wallet.get("balance", 0),
            "recipientWalletAfter": recipient_new_balance,
            "status": "completed",
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }

        if 'transactions' not in db.list_collection_names():
            db.create_collection('transactions')
        transactions_collection = db.transactions
        transaction_result = transactions_collection.insert_one(transaction)

        # Get user details for email notifications
        sender_user = users_collection.find_one({"_id": sender_id})
        recipient_user = users_collection.find_one({"_id": recipient_wallet["userId"]})

        # Wallet IDs for email content
        sender_wallet_id_for_email = sender_wallets[0]["walletId"] if sender_wallets else "Unknown"
        recipient_wallet_id_for_email = recipient_wallet_id

        # Send email notifications
        if sender_user and sender_user.get("email"):
            sender_subject = "Money Sent Successfully 💸"
            sender_body = f"""
<p>Dear {sender_user.get('first_name', 'User').capitalize()},</p>

<p>Your transfer of <strong>{amount} HTG</strong> from wallet <strong>{sender_wallet_id_for_email}</strong> to wallet <strong>{recipient_wallet_id_for_email}</strong> has been successfully completed.</p>

<h4>Transaction Summary</h4>
<ul>
  <li><strong>Amount Sent:</strong> {amount} HTG</li>
  <li><strong>Transfer Fee:</strong> 0 HTG (Free)</li>
  <li><strong>Total Deducted:</strong> {amount} HTG</li>
  <li><strong>Recipient Wallet:</strong> {recipient_wallet_id_for_email}</li>
  <li><strong>Transaction ID:</strong> {transaction_result.inserted_id}</li>
</ul>

<p>Thank you for choosing <strong>KrediNou</strong>. We appreciate your trust in our service.</p>

<p>Best regards,<br><strong>The KrediNou Team</strong></p>
"""
            send_brevo_email(sender_user["email"], sender_subject, sender_body)

        if recipient_user and recipient_user.get("email"):
            recipient_subject = "You Received Money! 🎉"
            recipient_body = f"""
<p>Dear {recipient_user.get('first_name', 'User').capitalize()},</p>

<p>You’ve received <strong>{amount} HTG</strong> from wallet <strong>{sender_wallet_id_for_email}</strong> to your wallet <strong>{recipient_wallet_id_for_email}</strong>.</p>

<h4>Transaction Details</h4>
<ul>
  <li><strong>Amount Received:</strong> {amount} HTG</li>
  <li><strong>Sender Wallet:</strong> {sender_wallet_id_for_email}</li>
  <li><strong>Transaction ID:</strong> {transaction_result.inserted_id}</li>
  <li><strong>Note:</strong> {note or 'No note provided'}</li>
</ul>

<p>The funds have been credited to your KrediNou wallet and are available for use immediately.</p>

<p>Thank you for being part of the <strong>KrediNou</strong> community!</p>
"""
            send_brevo_email(recipient_user["email"], recipient_subject, recipient_body)

        # Calculate sender's new balance
        sender_new_balance = sum(w.get("balance", 0) for w in wallets_collection.find({"userId": sender_id}))

        return jsonify({
            "success": True,
            "message": "Money sent successfully",
            "transactionId": str(transaction_result.inserted_id),
            "amountSent": amount,
            "fee": 0,
            "senderNewBalance": sender_new_balance,
            "recipientNewBalance": recipient_new_balance
        }), 200

    except Exception as e:
        print(f"❌ Error sending money: {e}")
        traceback.print_exc()
        return jsonify({"error": "Failed to process transaction"}), 500

# -----------------------------
# Route: Get user's wallets
# -----------------------------
@wallet_bp.route("/user/<user_id>", methods=["GET", "OPTIONS"])
def get_user_wallets(user_id):
    if request.method == "OPTIONS":
        return '', 200

    try:
        # Sync wallets first to ensure they're up to date
        sync_wallet(user_id)
        
        # Get all wallets for the user
        wallets = list(wallets_collection.find({"userId": user_id}))
        
        wallet_list = []
        for wallet in wallets:
            # Get loan details for each wallet
            loan = loans_collection.find_one({"_id": wallet["loanId"]})
            wallet_list.append({
                "walletId": wallet.get("walletId"),
                "balance": wallet.get("balance", 0),
                "currency": wallet.get("currency", "HTG"),
                "loanAmount": loan.get("amount", 0) if loan else 0,
                "createdAt": wallet.get("createdAt").isoformat() if wallet.get("createdAt") else None
            })
        
        return jsonify(wallet_list), 200

    except Exception as e:
        print(f"❌ Error getting user wallets: {e}")
        return jsonify({"error": "Failed to get user wallets"}), 500

@wallet_bp.route("/transactions/sent", methods=["GET"])
def get_sent_transactions():
    try:
        user_id = request.args.get("userId")
        if not user_id:
            return jsonify({"error": "Missing userId"}), 400

        transactions = list(
            db.transactions.find({"senderId": user_id}).sort("createdAt", DESCENDING)
        )

        for tx in transactions:
            recipient = db.users.find_one({"userId": tx.get("recipientId")})
            tx["_id"] = str(tx["_id"])
            created_at = tx.get("createdAt")
            tx["createdAt"] = created_at.isoformat() if isinstance(created_at, datetime) else created_at
            tx["recipientName"] = (
                f"{recipient.get('first_name','')} {recipient.get('last_name','')}".strip()
                if recipient else "Unknown"
            )

        return jsonify({"transactions": transactions})
    except Exception as e:
        print("❌ Error in /transactions/sent:", e)
        return jsonify({"error": "Server error"}), 500


from pymongo import DESCENDING
from datetime import datetime

@wallet_bp.route("/transactions/received", methods=["GET"])
def get_received_transactions():
    try:
        user_id = request.args.get("userId")
        if not user_id:
            return jsonify({"error": "Missing userId"}), 400

        transactions = list(
            db.transactions.find({"recipientId": user_id}).sort("createdAt", DESCENDING)
        )

        for tx in transactions:
            # Get the sender's wallet
            sender_wallet = db.wallets.find_one({"userId": tx.get("senderId")})
            tx["_id"] = str(tx["_id"])
            created_at = tx.get("createdAt")
            tx["createdAt"] = created_at.isoformat() if isinstance(created_at, datetime) else created_at

            # Set senderWalletId
            if sender_wallet:
                tx["senderWalletId"] = sender_wallet.get("walletId", "Unknown")
            else:
                tx["senderWalletId"] = "Unknown"

        return jsonify({"transactions": transactions})
    except Exception as e:
        print("❌ Error in /transactions/received:", e)
        return jsonify({"error": "Server error"}), 500
