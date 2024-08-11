print("Importing configurations... (models) ")
from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField
from flask_wtf.file import FileField, FileRequired
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

from app import db

print("Configuration (models) imported.")

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken.')
        

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


class Lehrveranstaltung(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    encoded_name = db.Column(db.String(255), nullable=False)
    ects = db.Column(db.Integer, nullable=True)
    professor = db.Column(db.String(255), nullable=True)
    difficulty = db.Column(db.String(255), nullable=True)
    time_spent = db.Column(db.String(255), nullable=True)
    uploads = db.relationship('Upload', backref='Lehrveranstaltung', lazy=True)

    def __repr__(self):
        return f'<Lehrveranstaltung {self.name}>'


class UploadFileForm(FlaskForm):
    file = FileField('File', validators=[FileRequired()])
    filename = StringField('Filename')
    Lehrveranstaltung_id = HiddenField('Lehrveranstaltung_id', validators=[DataRequired()])
    uploaded_by = HiddenField('Uploaded_by', validators=[DataRequired()])
    upload_date = HiddenField('Upload_date', validators=[DataRequired()])
    submit = SubmitField('Upload')

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    Lehrveranstaltung_id = db.Column(db.Integer, db.ForeignKey('lehrveranstaltung.id'), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime)
    likes = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<Upload {self.filename}>'
    

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('upload.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Like {self.upload_id} by {self.user_id}>'