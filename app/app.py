from flask import Flask, render_template, flash, redirect, url_for, abort, send_from_directory, jsonify
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
from datetime import datetime

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
    file = FileField('File', validators=[FileRequired()])
    submit = SubmitField('Upload')

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    lv = db.Column(db.String(255), nullable=False)
    uploaded_by = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<Upload {self.filename}>'
    

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('upload.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Like {self.upload_id} by {self.user_id}>'

    

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

@app.route('/lvs')
@login_required
def lvs():
    lvs = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('lvs.html', lvs=lvs)


@app.route('/lv/<lv>', methods=['GET', 'POST'])
@login_required
def lv_detail(lv):
    lv_folder = os.path.join(app.config['UPLOAD_FOLDER'], lv)
    if not os.path.exists(lv_folder):
        abort(404)

    form = UploadFileForm()
    if form.validate_on_submit():
        f = form.file.data
        filename = secure_filename(f.filename)
        f.save(os.path.join(lv_folder, filename))

        # Save upload information to the database
        upload = Upload(
            filename=filename,
            lv=lv,
            uploaded_by=current_user.username,
        )
        db.session.add(upload)
        db.session.commit()

        flash('File uploaded successfully.', 'success')
        return redirect(url_for('lv_detail', lv=lv))

    uploads = Upload.query.filter_by(lv=lv).all()
    return render_template('lv_detail.html', lv=lv, uploads=uploads, form=form)



@app.route('/like/<int:upload_id>', methods=['POST'])
@login_required
def like_upload(upload_id):
    upload = Upload.query.get_or_404(upload_id)
    if not has_user_liked(upload_id, current_user.id):
        upload.likes += 1
        db.session.commit()
        # Save the like to the database
        like = Like(upload_id=upload_id, user_id=current_user.id)
        db.session.add(like)
        db.session.commit()
        return jsonify(success=True, likes=upload.likes)
    else:
        return jsonify(success=False, message='You have already liked this upload.')
    

def has_user_liked(upload_id, user_id):
    return Like.query.filter_by(upload_id=upload_id, user_id=user_id).first() is not None

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('logout'))


if __name__ == '__main__':
    app.run(debug=True)