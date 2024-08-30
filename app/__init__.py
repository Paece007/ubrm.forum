from flask import Flask, request, render_template, session # Import the request object
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect, CSRFError
import logging
import tempfile


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

    logging.debug(f"CSRF Protection enabled: {app.config['WTF_CSRF_ENABLED']}")
    logging.debug(f"Session type: {app.config['SESSION_TYPE']}")
    logging.debug(f"Session SQLAlchemy: {app.config['SESSION_SQLALCHEMY']}")

    logging.warning(f"CSRF Protection enabled: {app.config['WTF_CSRF_ENABLED']}")
    logging.warning(f"Session type: {app.config['SESSION_TYPE']}")
    logging.warning(f"Session SQLAlchemy: {app.config['SESSION_SQLALCHEMY']}")

    app.logger.info(f"CSRF Protection enabled: {app.config['WTF_CSRF_ENABLED']}")
    app.logger.info(f"Session type: {app.config['SESSION_TYPE']}")
    app.logger.info(f"Session SQLAlchemy: {app.config['SESSION_SQLALCHEMY']}")

    @app.before_request
    def log_csrf_token():
        token = request.cookies.get('csrf_token')
        logging.debug(f"CSRF Token from cookie: {token}")
        form_token = request.form.get('csrf_token')
        logging.debug(f"CSRF Token from form: {form_token}")
        logging.debug(f"Session contents: {session.items()}")
        if not token:
            logging.warning("CSRF token not found in cookies.")
        if not form_token:
            logging.warning("CSRF token not found in form.")

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return render_template('csrf_error.html', reason=e.description), 400
    
    @app.errorhandler(500)
    def handle_internal_server_error(e):
        return render_template('500_error.html', error=str(e)), 500

    with app.app_context():
        db.create_all()

    return app