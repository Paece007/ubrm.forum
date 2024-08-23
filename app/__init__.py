from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
import logging
import os


from config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_view = 'login'
csrf = CSRFProtect()
# Configure logging
logging.basicConfig(level=logging.INFO)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure the instance path exists
    os.makedirs(app.config['INSTANCE_PATH'], exist_ok=True)
    app.instance_path = app.config['INSTANCE_PATH']

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)  # Ensure CSRF protection is enabled globally

    with app.app_context():
        db.create_all()

    return app