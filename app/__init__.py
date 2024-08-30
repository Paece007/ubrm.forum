from flask import Flask, request  # Import the request object
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
import logging
import tempfile
import os


from config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'login'
csrf = CSRFProtect()
sess=Session()
# Configure logging
logging.basicConfig(level=logging.INFO)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Override instance_path to a temporary directory
    app.instance_path = tempfile.mkdtemp()

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)  # Ensure CSRF protection is enabled globally
    app.config['SESSION_SQLALCHEMY'] = db
    sess.init_app(app)

    logging.info(f"CSRF Protection enabled: {app.config['WTF_CSRF_ENABLED']}")

    @app.before_request
    def log_csrf_token():
        token = request.cookies.get('csrf_token')
        logging.info(f"CSRF Token from cookie: {token}")
        form_token = request.form.get('csrf_token')
        logging.info(f"CSRF Token from form: {form_token}")
        if not token:
            logging.warning("CSRF token not found in cookies.")
        if not form_token:
            logging.warning("CSRF token not found in form.")

    with app.app_context():
        db.create_all()

    return app