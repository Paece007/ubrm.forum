from flask import Flask, render_template, flash, redirect, url_for, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from flask_wtf.file import FileField, FileRequired
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
from werkzeug.utils import secure_filename

load_dotenv()

# Import the configuration
from config import Config

# Create the Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Create the SQLAlchemy object
db = SQLAlchemy(app)

# Create the Bcrypt object
bcrypt = Bcrypt(app)

# Create the LoginManager object
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create a user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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



class UploadFileForm(FlaskForm):
    file = FileField(validators=[FileRequired()])
    submit = SubmitField('Upload')

    

@app.route('/')
def index():
    return render_template('index.html')



@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = UploadFileForm()
    if form.validate_on_submit():
        f = form.file.data
        filename = secure_filename(f.filename)
        f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash('File uploaded successfully.', 'success')
        return 'File uploaded successfully.'

    return render_template('upload.html', form=form)

@app.route('/download')
@login_required
def download():
    try:
        # Ensure the upload folder exists
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            print(f"Upload folder '{app.config['UPLOAD_FOLDER']}' does not exist.")
            abort(500)
        
        # List all files in the directory
        files = os.listdir(app.config['UPLOAD_FOLDER'])
        print(f"Files found: {files}")
        return render_template('download.html', files=files)
    except Exception as e:
        print(f"Error: {e}")
        abort(500)


@app.route('/download/<filename>')
@login_required
def download_file(filename):
    try:
        # Ensure the upload folder exists
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            print(f"Upload folder '{app.config['UPLOAD_FOLDER']}' does not exist.")
            abort(500)
        
        # Secure the filename
        filename = secure_filename(filename)
        
        # Send the file from the upload folder
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        print(f"Error: {e}")
        abort(500)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/protected')
@login_required
def protected():
    return 'Logged in as: ' + str(current_user.id)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('logout'))


if __name__ == '__main__':
    app.run(debug=True)