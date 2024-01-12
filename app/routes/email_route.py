# routes/email_route.py
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user, LoginManager
from pymongo import MongoClient, DESCENDING
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

email_bp = Blueprint('email', __name__)

# MongoDB configuration
MONGO_URI = 'mongodb://localhost:27017/'
DB_NAME = 'smtp-email-app'
COLLECTION_NAME = 'mails'

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
mails_collection = db[COLLECTION_NAME]

@LoginManager.unauthorized_handler(self=LoginManager, callback=redirect(url_for('auth.login')))
def unauthorized():
    flash('You need to login or register first.', 'danger')
    return render_template('login.html')


@email_bp.route('/email')
@login_required
def index():
    return render_template('email.html', username=current_user.username, email=current_user.email)


@email_bp.route('/email/send', methods=['GET','POST'])
@login_required
def send_email():
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
        try:
            failed_recipients = server.sendmail(sender, recipients.split(','), msg.as_string())
            success = not failed_recipients
        except Exception as e:
            failed_recipients = recipients.split(',')
            success = False

    log_entry = {
        'sender': sender,
        'recipients': recipients,
        'subject': subject,
        'datetime_utc': datetime.utcnow(),
        'success': success,
        'failed_recipients': failed_recipients,
    }
    
    # Create or get the subcollection for the current user
    user_mail_logs_collection = mails_collection[f'user_{current_user.id}_logs']

    # Insert the log entry into the user's subcollection
    user_mail_logs_collection.insert_one(log_entry)

    # Pass log data to the template
    return render_template('send_result.html', log_entry=log_entry, success=success)

    

@email_bp.route('/email/logs')
@login_required
def email_logs():
    email_logs = mails_collection[f'user_{current_user.id}_logs'].find().sort("datetime_utc", DESCENDING)
    return render_template('email_logs.html', email_logs=email_logs)



