# app/config.py
import secrets
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
    print(f"DATABASE_URL: {os.environ.get('DATABASE_URL')}")
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    print(f"SQLALCHEMY_DATABASE_URI: {SQLALCHEMY_DATABASE_URI}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False