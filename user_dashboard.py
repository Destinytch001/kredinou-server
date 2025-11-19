from flask import Blueprint, jsonify, request
from datetime import datetime, timezone
from bson import ObjectId
from extensions import get_db
from decorators import token_required
import logging

# Setup
db = get_db()
loans_collection = db.loans
users_collection = db.users

user_dashboard_bp = Blueprint("user_dashboard", __name__, url_prefix="/api/dashboard")
logger = logging.getLogger(__name__)


@user_dashboard_bp.route("/summary", methods=["GET"])
@token_required
def get_dashboard_summary(current_user):
    """
    Returns a summary for the user's dashboard:
    - total loan count
    - withdrawal count (disbursed loans)
    - active loan amount + interest (10%)
    - next due date
    """
    try:
        loans = list(loans_collection.find({"userId": current_user["_id"]}))
        total_loans = len(loans)
        withdrawals = sum(1 for l in loans if l.get("disbursementStatus") == "completed")

        # Active loans are approved/disbursed
        active_loans = [l for l in loans if l["status"] in ["approved", "disbursed"]]
        total_active_amount = sum(l["amount"] * 1.10 for l in active_loans)  # add 10% interest

        next_due_date = None
        for l in active_loans:
            if l.get("dueDate"):
                if next_due_date is None or l["dueDate"] < next_due_date:
                    next_due_date = l["dueDate"]

        return jsonify({
            "totalLoans": total_loans,
            "withdrawals": withdrawals,
            "activeLoanAmountWithInterest": round(total_active_amount, 2),
            "nextDueDate": next_due_date.isoformat() if next_due_date else None
        }), 200

    except Exception as e:
        logger.error(f"Dashboard summary error: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to fetch dashboard summary"}), 500


@user_dashboard_bp.route("/history", methods=["GET"])
@token_required
def get_loan_history(current_user):
    """
    Returns loan history for charting (date + amount)
    """
    try:
        loans = list(loans_collection.find(
            {"userId": current_user["_id"]},
            {"applicationDate": 1, "amount": 1, "_id": 0}
        ).sort("applicationDate", 1))

        history = [
            {
                "date": loan["applicationDate"].isoformat(),
                "amount": loan["amount"]
            }
            for loan in loans if loan.get("applicationDate")
        ]

        return jsonify(history), 200

    except Exception as e:
        logger.error(f"Loan history error: {str(e)}", exc_info=True)
        return jsonify({"error": "Failed to fetch loan history"}), 500
