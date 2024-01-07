# routes/email.py
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app import login_manager

email_bp = Blueprint('email', __name__)

# ... (existing code)

@email_bp.route('/email')
@login_required
def index():
    return render_template('email.html', username=current_user.username, email=current_user.email)

# @email_bp.route('/login_required')
# def login_required_page():
#     return render_template('login_required.html')
