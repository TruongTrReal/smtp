import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_otp_email(from_email, to_email, otp_code):
    SMTP_SERVER = 'localhost'
    SMTP_PORT = 25

    subject = 'TruongGPT OTP'
    body = f"""
    Hello,

    Thank you for using truonggpt.com. To complete your login, please enter the following OTP:

    OTP: {otp_code}

    This OTP is valid for a short period, so please enter it promptly. If you did not request this OTP, please ignore this email.

    Thank you,
    TruongGPT Team
    """

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            print('from_addr=',from_email,' to_addrs=', to_email, 'msg=', msg.as_string())
            server.sendmail(from_addr=from_email, to_addrs=to_email, msg=msg.as_string())
        print("OTP email sent successfully.")
    except Exception as e:
        print(f"Error sending OTP email: {e}")

# Example usage:
# from_email = 'noreply@truonggpt.com'
# to_email = 'truongibfx4you@gmail.com'
# otp_code = '452674'
# send_otp_email(from_email, to_email, otp_code)
