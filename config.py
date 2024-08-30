# app/config.py
import secrets
import os
from datetime import timedelta  # Add this line to import the timedelta class from the datetime module
from flask_sqlalchemy import SQLAlchemy

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_TYPE = 'sqlalchemy'
    SESSION_SQLALCHEMY = SQLAlchemy()
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)