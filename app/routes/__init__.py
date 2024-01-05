# app/routes/__init__.py
from .auth import auth_bp
from .welcome import welcome_bp
from .email import email_bp
# Add more blueprint imports if needed

def init_app(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(welcome_bp)
    app.register_blueprint(email_bp)

    # Register additional blueprints here
