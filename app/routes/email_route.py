# routes/email_route.py
from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app import login_manager
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

email_bp = Blueprint('email', __name__)


@email_bp.route('/email')
@login_required
def index():
    return render_template('email.html', username=current_user.username, email=current_user.email)


@email_bp.route('/email/send', methods=['POST'])
@login_required
def send_email():
    try:
        sender = request.form['sender']
        recipients = request.form['recipients']
        subject = request.form['subject']
        message = request.form['message']
        is_html = request.form.get('isHtml', 'false').lower() == 'true'


        # Handling attachments
        attachments = request.files.getlist('attachments')
        attached_files = []
        for attachment in attachments:
            attached_files.append({
                'filename': attachment.filename,
                'content': attachment.read(),
            })

        # Send email
        SMTP_SERVER = 'localhost'
        SMTP_PORT = 25

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipients
        msg['Subject'] = subject

        if is_html:
            html_part = MIMEText(message, 'html')
            msg.attach(html_part)
        else:
            # If not HTML, use plain text only
            msg.attach(MIMEText(message, 'plain'))

        for attachment in attached_files:
            attached_file = MIMEApplication(attachment['content'])
            attached_file.add_header('Content-Disposition', 'attachment', filename=attachment['filename'])
            msg.attach(attached_file)

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.sendmail(sender, recipients.split(','), msg.as_string())

        return jsonify({'message': 'Email sent successfully!'}), 200

    except Exception as e:
        return jsonify({'message': f'Error sending email: {str(e)}'}), 500