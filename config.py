# app/config.py
import secrets
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    INSTANCE_PATH = os.environ.get('INSTANCE_PATH') or '/tmp/instance'