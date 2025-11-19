from flask import Blueprint, request, jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Define Blueprint
contact_bp = Blueprint("contact_bp", __name__)

# Hardcoded SMTP credentials
SMTP_SERVER = "smtp.hostinger.com"
SMTP_PORT = 465
SMTP_USER = "support@kredinou.com"
SMTP_PASS = "D45192091425Ea@"

def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg["From"] = "KrediNou <support@kredinou.com>" 
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_USER, to_email, msg.as_string())

@contact_bp.route('/api/contact', methods=['POST'])
def contact():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    subject = data.get("subject")
    message = data.get("message")

    if not all([name, email, subject, message]):
        return jsonify({"success": False, "error": "All fields are required"}), 400

    try:
        # Email to support
        support_body = f"""
        New contact message from {name} <{email}>
        
        Subject: {subject}

        Message:
        {message}
        """
        send_email(SMTP_USER, f"New Contact Message: {subject}", support_body)

        # Confirmation email to user
        user_body = f"""
        Hello {name},

        Thank you for contacting KrediNou! We have received your message and will get back to you shortly.

        Best regards,
        KrediNou Team
        """
        send_email(email, "Your message has been received!", user_body)

        return jsonify({"success": True, "message": "Message sent successfully!"}), 200

    except Exception as e:
        print("Email sending failed:", e)
        return jsonify({"success": False, "error": "Failed to send email"}), 500
