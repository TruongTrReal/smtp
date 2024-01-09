# routes/email.py
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app import login_manager
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

email_bp = Blueprint('email', __name__)


@email_bp.route('/email')
@login_required
def index():
    return render_template('email.html', username=current_user.username, email=current_user.email)


@app.route('/email/send', methods=['POST'])
def send_email():
    try:
        sender = request.form['sender']
        recipients = request.form['recipients']
        subject = request.form['subject']
        message = request.form['message']

        # You may want to add more logic to handle attachments, if needed

        # Send email
        SMTP_SERVER = 'localhost'
        SMTP_PORT = 25

        email_body = f"""
        {message}
        """

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipients
        msg['Subject'] = subject
        msg.attach(MIMEText(email_body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.sendmail(sender, recipients.split(','), msg.as_string())

        return jsonify({'message': 'Email sent successfully!'}), 200

    except Exception as e:
        return jsonify({'message': f'Error sending email: {str(e)}'}), 500
