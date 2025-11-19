from flask import Blueprint, jsonify
from flask_cors import CORS
from bson import ObjectId
from datetime import datetime, timedelta
from extensions import get_db
from pymongo import ASCENDING

dashboard_bp = Blueprint("dashboard_bp", __name__)
CORS(dashboard_bp, resources={r"/*": {"origins": [
    "https://destinytch.com.ng",
    "https://www.destinytch.com.ng",
    "https://kredinou.com",
    "https://www.kredinou.com",
    "http://localhost:5000",
    "http://127.0.0.1:5000"
]}}, supports_credentials=True)

# MongoDB collections
db = get_db()
users_col = db.users
loans_col = db.loans
repayments_col = db.repayments
withdrawals_col = db.withdrawals

# Helper to serialize MongoDB documents
def serialize_doc(doc):
    for k, v in doc.items():
        if isinstance(v, ObjectId):
            doc[k] = str(v)
        elif isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc

# ------------------------
# DASHBOARD SUMMARY
# ------------------------
@dashboard_bp.route("/admin/dashboard/summary", methods=["GET"])
def dashboard_summary():
    try:
        # Count all users (since users collection stores all users)
        total_users = users_col.count_documents({})
        
        # Count only approved/disbursed loans (not pending or rejected)
        total_loans = loans_col.count_documents({
            "status": {"$in": ["approved", "disbursed", "repaid"]}
        })
        
        # Count only verified repayments
        total_repayments = repayments_col.count_documents({
            "status": "verified"
        })
        
        # Count only approved withdrawals (not rejected)
        total_withdrawals = withdrawals_col.count_documents({
            "status": "approved"
        })
        
        # Calculate total amounts for approved transactions only
        total_loan_amount = sum([loan.get('amount', 0) for loan in loans_col.find({
            "status": {"$in": ["approved", "disbursed", "repaid"]}
        })])
        
        total_repayment_amount = sum([repayment.get('amount', 0) for repayment in repayments_col.find({
            "status": "verified"
        })])
        
        total_withdrawal_amount = sum([withdrawal.get('amount', 0) for withdrawal in withdrawals_col.find({
            "status": "approved"
        })])

        return jsonify({
            "total_users": total_users,
            "total_loans": total_loans,
            "total_repayments": total_repayments,
            "total_withdrawals": total_withdrawals,
            "total_loan_amount": total_loan_amount,
            "total_repayment_amount": total_repayment_amount,
            "total_withdrawal_amount": total_withdrawal_amount
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------------
# DASHBOARD CHART DATA
# ------------------------
@dashboard_bp.route("/admin/dashboard/chart-data", methods=["GET"])
def dashboard_chart_data():
    try:
        # Get date range (last 30 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        # =====================
        # Loans (by disbursedAt) - only approved/disbursed/repaid
        # =====================
        loans_pipeline = [
            {"$match": {
                "disbursedAt": {"$ne": None, "$gte": start_date, "$lte": end_date},
                "status": {"$in": ["approved", "disbursed", "repaid"]}
            }},
            {"$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%Y-%m-%d",
                        "date": "$disbursedAt"
                    }
                },
                "total": {"$sum": {"$toDouble": "$amount"}}
            }},
            {"$sort": {"_id": ASCENDING}}
        ]
        loans_data = list(loans_col.aggregate(loans_pipeline))

        # =====================
        # Repayments (by date) - only verified
        # =====================
        repayments_pipeline = [
            {"$match": {
                "createdAt": {"$ne": None, "$gte": start_date, "$lte": end_date},
                "status": "verified"
            }},
            {"$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%Y-%m-%d",
                        "date": "$createdAt"
                    }
                },
                "total": {"$sum": {"$toDouble": "$amount"}}
            }},
            {"$sort": {"_id": ASCENDING}}
        ]
        repayments_data = list(repayments_col.aggregate(repayments_pipeline))

        # =====================
        # Withdrawals (by createdAt) - only approved (not rejected)
        # =====================
        withdrawals_pipeline = [
            {"$match": {
                "createdAt": {"$ne": None, "$gte": start_date, "$lte": end_date},
                "status": "approved"
            }},
            {"$group": {
                "_id": {
                    "$dateToString": {
                        "format": "%Y-%m-%d",
                        "date": "$createdAt"
                    }
                },
                "total": {"$sum": {"$toDouble": "$amount"}}
            }},
            {"$sort": {"_id": ASCENDING}}
        ]
        withdrawals_data = list(withdrawals_col.aggregate(withdrawals_pipeline))

        # Fill in missing dates with zero values
        all_dates = set()
        for dataset in [loans_data, repayments_data, withdrawals_data]:
            for item in dataset:
                all_dates.add(item["_id"])
        
        all_dates = sorted(list(all_dates))
        
        def fill_missing_dates(data, dates):
            data_dict = {item["_id"]: item["total"] for item in data}
            return [{"_id": date, "total": data_dict.get(date, 0)} for date in dates]
        
        loans_data_filled = fill_missing_dates(loans_data, all_dates)
        repayments_data_filled = fill_missing_dates(repayments_data, all_dates)
        withdrawals_data_filled = fill_missing_dates(withdrawals_data, all_dates)

        return jsonify({
            "loans": loans_data_filled,
            "repayments": repayments_data_filled,
            "withdrawals": withdrawals_data_filled
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ------------------------
# RECENT ACTIVITIES
# ------------------------
@dashboard_bp.route("/admin/dashboard/recent-activities", methods=["GET"])
def recent_activities():
    try:
        # Get recent loans (approved/disbursed/repaid only)
        recent_loans = list(loans_col.find({
            "status": {"$in": ["approved", "disbursed", "repaid"]}
        }).sort("createdAt", -1).limit(5))
        
        # Get recent repayments (verified only)
        recent_repayments = list(repayments_col.find({
            "status": "verified"
        }).sort("createdAt", -1).limit(5))
        
        # Get recent withdrawals (approved only)
        recent_withdrawals = list(withdrawals_col.find({
            "status": "approved"
        }).sort("createdAt", -1).limit(5))
        
        # Serialize the documents
        recent_loans = [serialize_doc(loan) for loan in recent_loans]
        recent_repayments = [serialize_doc(repayment) for repayment in recent_repayments]
        recent_withdrawals = [serialize_doc(withdrawal) for withdrawal in recent_withdrawals]
        
        return jsonify({
            "recent_loans": recent_loans,
            "recent_repayments": recent_repayments,
            "recent_withdrawals": recent_withdrawals
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ------------------------
# USER STATISTICS
# ------------------------
@dashboard_bp.route("/admin/dashboard/user-stats", methods=["GET"])
def user_stats():
    try:
        # Count users by status
        user_stats = list(users_col.aggregate([
            {"$group": {
                "_id": "$status",
                "count": {"$sum": 1}
            }}
        ]))
        
        # Count users by department
        users_by_department = list(users_col.aggregate([
            {"$group": {
                "_id": "$department",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}}
        ]))
        
        # Count users by verification status
        users_by_verification = list(users_col.aggregate([
            {"$group": {
                "_id": "$verification_status",
                "count": {"$sum": 1}
            }}
        ]))
        
        return jsonify({
            "user_stats": user_stats,
            "users_by_department": users_by_department,
            "users_by_verification": users_by_verification
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------------
# USER LOAN DETAILS WITH INTEREST
# ------------------------
@dashboard_bp.route("/admin/dashboard/user/<user_id>/loans", methods=["GET"])
def user_loan_details(user_id):
    try:
        # Find user
        user = users_col.find_one({"_id": user_id})
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Find all loans for the user
        loans_cursor = loans_col.find({"userId": user_id})
        loans = list(loans_cursor)

        if not loans:
            return jsonify({
                "user": f"{user.get('first_name')} {user.get('last_name')}",
                "total_loans_amount": 0,
                "active_loans": []
            }), 200

        total_loans_amount = 0
        active_loans = []

        for loan in loans:
            amount = loan.get("amount", 0)
            status = loan.get("status")
            total_loans_amount += amount

            if status == "disbursed":
                # Base interest: 10% of the principal
                interest = 0.1 * amount
                due_date_str = loan.get("dueDate", {}).get("$date")
                due_date = None
                overdue_months = 0

                if due_date_str:
                    due_date = datetime.fromisoformat(due_date_str.replace("Z", "+00:00"))
                    # Calculate overdue months
                    today = datetime.utcnow()
                    if today > due_date:
                        delta_days = (today - due_date).days
                        overdue_months = delta_days // 30
                        # Add 5% per month overdue
                        interest += 0.05 * amount * overdue_months

                active_loans.append({
                    "loan_id": str(loan["_id"]),
                    "loan_type": loan.get("loanType"),
                    "amount": amount,
                    "interest_due": round(interest, 2),
                    "due_date": due_date.isoformat() if due_date else None,
                    "overdue_months": overdue_months
                })

        return jsonify({
            "user": f"{user.get('first_name')} {user.get('last_name')}",
            "total_loans_amount": total_loans_amount,
            "active_loans": active_loans
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

