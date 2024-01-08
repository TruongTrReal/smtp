# app/__init__.py
from flask import Flask
from flask_pymongo import PyMongo
from flask_login import LoginManager
from flask_mail import Mail

app = Flask(__name__)
mongo = PyMongo()
login_manager = LoginManager(app)
mail = Mail()

def create_app():

    # Initialize Flask-Login
    login_manager.init_app(app)

    # Set a secret key for session security
    app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a strong, random secret key

    # Configure the app for Flask-PyMongo
    app.config['MONGO_URI'] = 'mongodb://localhost:27017/smtp-email-app'
    mongo.init_app(app)

    # Configure the app for Flask-Mail
    app.config['MAIL_SERVER'] = 'truonggpt.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = 'your-email@truonggpt.com'  # Replace with your email
    mail.init_app(app)

    from app.routes import init_app
    init_app(app)

    return app
