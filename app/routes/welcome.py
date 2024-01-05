from flask import Blueprint, render_template

welcome_bp = Blueprint('home', __name__)

@welcome_bp.route('/')
def index():
    # You can perform any necessary logic here before rendering the template
    # For example, check if the user is already logged in and redirect if needed
    # Or perform other setup actions

    return render_template('index.html')
