# routes/email.py
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app import login_manager

email_bp = Blueprint('email', __name__)

# ... (existing code)

@email_bp.route('/email')
@login_required
def index():
    # user = current_user
    return render_template('email.html')
