# app/config.py
import secrets
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
    print(f"DATABASE_URL: {os.environ.get('DATABASE_URL')}")
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://ubrm-forum_owner:TYwS1sBaE3HM@ep-odd-forest-a294zmzw.eu-central-1.aws.neon.tech/ubrm-forum?sslmode=require'
    print(f"SQLALCHEMY_DATABASE_URI: {SQLALCHEMY_DATABASE_URI}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'