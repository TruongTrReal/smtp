# app/routes/authentication.py 
import os
from flask import Blueprint, render_template, redirect, url_for, flash, session, request
from werkzeug.security import generate_password_hash, check_password_hash
from app import mongo, login_manager
from app.models import User
from flask_oauthlib.client import OAuth
from flask_login import login_user, logout_user
import uuid
import google.oauth2.credentials
import google_auth_oauthlib.flow


CLIENT_SECRETS_FILE = os.path.join(os.path.dirname(__file__), "client-secret.json")

SCOPES = ['https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/drive.metadata.readonly openid']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'

auth_bp = Blueprint('auth', __name__)
oauth = OAuth()

google = oauth.remote_app(
    'google',
    consumer_key='294737311113-vi4mnctcscovl0tgvg6eesgo16v56i8p.apps.googleusercontent.com',
    consumer_secret='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',
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

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
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
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


@auth_bp.route('/login/google')
def google_login():
    return google.authorize(callback=url_for('auth.google_login', _external=True))


@auth_bp.route('/login/google/authorized')
def google_authorized():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        flash('Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        ))
        return redirect(url_for('auth.login'))

    google_user = google.get('userinfo')
    email = google_user.data.get('email')

    # Check if the email already exists in the database
    existing_user = mongo.db.users.find_one({'email': email})
    if existing_user:
        flash('Login successful!', 'success')
        return redirect(url_for('email.index'))

    # Email not found, save the user to the database
    new_user = {'email': email}
    mongo.db.users.insert_one(new_user)

    flash('Google login successful! User registered.', 'success')
    return redirect(url_for('home.index'))

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        user_id = uuid.uuid4().hex
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if the email already exists in the database
        existing_user = mongo.db.users.find_one({'email': email})
        if existing_user:
            flash('Email already registered. Please log in or use a different email.', 'danger')
            return redirect(url_for('auth.register'))
        

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256:600000')

        # Create a new user instance without saving to the database
        new_user = User(user_id=user_id, username=username, email=email, password=hashed_password)

        # Log in the user immediately after registration
        login_user(new_user)

        # Save user to MongoDB
        mongo.db.users.insert_one(new_user.__dict__)

        flash('Registration successful! You are now logged in.', 'success')
        return redirect(url_for('email.index'))

    return render_template('register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = mongo.db.users.find_one({'email': email})

        if user and check_password_hash(user['password'], password):
            # Use the User class to create a User object for login
            user_obj = User(
                user_id=user['_id'],
                username=user['username'],
                email=user['email'],
                password=user['password']
            )
            login_user(user_obj)  # Login the user
            flash('Login successful!', 'success')
            return redirect(url_for('email.index'))  # Redirect to a protected route
        else:
            flash('Login failed. Check your email and password.', 'danger')

    return render_template('login.html')


@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home.index'))