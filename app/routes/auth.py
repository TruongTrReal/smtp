# app/routes/authentication.py 
import os
from flask import Blueprint, render_template, redirect, url_for, flash, session, request
from flask_mail import Message, Mail
from werkzeug.security import generate_password_hash, check_password_hash
from app import mongo, mail
from app.models import User
from flask_oauthlib.client import OAuth
from flask_login import login_user, logout_user
import uuid
import google_auth_oauthlib.flow
import random



CLIENT_SECRETS_FILE = os.path.join(os.path.dirname(__file__), "client-secret.json")

SCOPES = ['https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/drive.metadata.readonly openid']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'

auth_bp = Blueprint('auth', __name__)
oauth = OAuth()

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

@auth_bp.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = url_for('auth.oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    session['state'] = state

    return redirect(authorization_url)


@auth_bp.route('/oauth2callback')
def oauth2callback():
    state = session.pop('state', None)
    
    if state is None:
        flash('Invalid state parameter received.', 'error')
        return redirect(url_for('auth.login'))
    
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('auth.oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('email.index'))



@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_id = uuid.uuid4().hex
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        existing_user = mongo.db.users.find_one({'email': email})

        if existing_user:
            flash('Email already registered. Please log in or use a different email.', 'danger')
            return redirect(url_for('auth.register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256:600000')        
        
        otp = str(random.randint(0, 999999))

        # Save the verification token and user details to the database
        new_user = User(
            user_id=user_id, 
            username=username, 
            email=email, 
            password=hashed_password, 
            verification_otp=otp,
            email_verified=False,
            )

        # Save user to MongoDB
        mongo.db.users.insert_one(new_user.__dict__)

        # Send verification email
        send_verification_email(email, otp)

        flash('Registration successful! Please check your email for verification.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


def send_verification_email(email, token):
    # Construct the verification link using a route in your app
    verification_link = url_for('auth.verify_email', token=token, _external=True)

    # Create the verification email message
    subject = 'Email Verification'
    body = f'To verify your email, click the following link: {verification_link}'
    
    # Send the email
    send_email(email, subject, body)


@auth_bp.route('/verify_email', methods=['GET'])
def verify_email():
    return render_template('email_verify.html')

def send_email(to, subject, body):
    # Use Flask-Mail to send the email
    msg = Message(subject, sender='noreply@truonggpt.com', recipients=[to])
    msg.body = body
    mail.send(msg)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = mongo.db.users.find_one({'email': email})

        if user and check_password_hash(user['password'], password):

            user_obj = User(
                user_id=user['id'],
                username=user['username'],
                email=email,
                password=user['password'],
                verification_otp=user['verification_otp'],
                email_verified=user['email_verified']
            )
            login_user(user_obj)

            print(login_user(user_obj))

            flash('Login successful!', 'success')
            
            return redirect(url_for('email.index'))
        
        else:
            flash('Login failed. Check your email and password.', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home.index'))