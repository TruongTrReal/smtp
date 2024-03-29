# app/routes/authentication.py 
from flask import Blueprint, render_template, redirect, url_for, flash, session, request
from werkzeug.security import generate_password_hash, check_password_hash
from app import mongo
from app.models import User
from flask_login import login_user, logout_user, LoginManager
import uuid
import random
from .send_otp import send_otp_email
from oauthlib.oauth2 import WebApplicationClient
import requests
import json

auth_bp = Blueprint('auth', __name__)
login_manager = LoginManager()

GOOGLE_CLIENT_ID = "294737311113-vi4mnctcscovl0tgvg6eesgo16v56i8p.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

client = WebApplicationClient(GOOGLE_CLIENT_ID)


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@login_manager.unauthorized_handler
def unauthorized():
    # do stuff
    flash('You need to login or register first.', 'danger')
    return redirect(url_for('auth.login'))


@auth_bp.route('/authorize')
def authorize():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@auth_bp.route("/authorize/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)   

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400
    
    random_pw = str(random.randint(0, 99999999999))
    hashed_password = generate_password_hash(random_pw, method='pbkdf2:sha256:600000')

    user = User(
            user_id=unique_id, 
            username=users_name, 
            email=users_email, 
            password=hashed_password, 
            verification_otp='email verified',
            email_verified=True,
        )
    
    session['user_id'] = unique_id
    
    existing_user = mongo.db.users.find_one({'email': users_email})

    if existing_user:
        flash('user exsist in database. Please login with password', 'danger')
        return redirect(url_for("auth.login"))
    else:
        mongo.db.users.insert_one(user.__dict__)

    login_user(user)
    return redirect(url_for("email.index"))

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
        
        otp = str(random.randint(100000, 999999))

        # Save the verification token and user details to the database
        new_user = User(
            user_id=user_id, 
            username=username, 
            email=email, 
            password=hashed_password, 
            verification_otp=otp,
            email_verified=False,
        )

        session['user_id'] = user_id
        # Send verification email
        send_otp_email("noreply@truonggpt.com", email, otp)

        # Save user to MongoDB
        mongo.db.users.insert_one(new_user.__dict__)
        flash('Registration successful! Please check your email for verification.', 'success')
        return render_template('email_verify.html')

    return render_template('register.html')

@auth_bp.route('/verify_email', methods=['GET','POST'])
def verify_email():
    if request.method == 'POST':
        user_id = session['user_id']
        # Get the OTP values from the form
        otp1 = request.form.get('otp1')
        otp2 = request.form.get('otp2')
        otp3 = request.form.get('otp3')
        otp4 = request.form.get('otp4')
        otp5 = request.form.get('otp5')
        otp6 = request.form.get('otp6')

        # Concatenate the OTP values to form the complete OTP
        entered_otp = f"{otp1}{otp2}{otp3}{otp4}{otp5}{otp6}"

        user_data = mongo.db.users.find_one({'id': user_id, 'verification_otp': entered_otp})

        if user_data:
            # Create an instance of the User class
            user_instance = User(
                user_id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                password=user_data['password'],
                verification_otp=user_data['verification_otp'],
                email_verified=user_data['email_verified']
            )
            login_user(user_instance)
            mongo.db.users.update_one({'id': user_id}, {'$set': {'email_verified': True}})
            flash('Email successfully verified.', 'success')
            return redirect(url_for('email.index'))
        else:
            flash('Invalid verification token. Please check your email or request a new OTP.', 'danger')

    return redirect(url_for('auth.login'))
       
@auth_bp.route('/resend_otp', methods=['GET','POST'])
def resend_otp():
    user_id = session['user_id']
    user_unverified = mongo.db.users.find_one({'id': user_id, 'email_verified': False})
    if user_unverified:
        # Generate a new OTP
        new_otp = str(random.randint(100000, 999999))
        email = user_unverified['email']
        # Update the user's verification OTP in the database
        mongo.db.users.update_one({'id': user_id}, {'$set': {'verification_otp': new_otp}})

        # Resend verification email with the new OTP
        send_otp_email("noreply@truonggpt.com", email, new_otp)

        flash('New OTP sent! Please check your email for verification.', 'success')
        return render_template('email_verify.html')
    else:
        flash('Invalid email or email is already verified.', 'danger')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = mongo.db.users.find_one({'email': email})

        if user and check_password_hash(user['password'][0], password) and user['email_verified']==True:

            user_obj = User(
                user_id=user['id'],
                username=user['username'],
                email=email,
                password=user['password'][0],
                verification_otp=user['verification_otp'][0],
                email_verified=user['email_verified']
            )

            session['user_id'] = user['id']
            login_user(user_obj)            
            return redirect(url_for('email.index'))
            
        elif user and check_password_hash(user['password'][0], password) and user['email_verified']!=True:
            flash('You have not verify email yet. Lets verify!', 'danger')
            return redirect(url_for('auth.resend_otp'))

        else:
            flash('Login failed. Check your email and password.', 'danger')

    return render_template('login.html')

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home.index'))