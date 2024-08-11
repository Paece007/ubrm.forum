# Import the configuration
print("Importing configuration...(App)")
from flask import Flask, render_template, flash, redirect, url_for, abort, send_from_directory, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect
from flask_login import login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from config import Config

print("Configuration imported. (App)")

load_dotenv()

from app import create_app, login_manager, db, bcrypt
from app.models import User, RegisterForm, LoginForm, Lehrveranstaltung, UploadFileForm, Upload, Like

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)


print("Importing models...(App)")
try:
    from app import models
    print("Models imported successfully. (App)")
except ModuleNotFoundError as e:
    print(f"Error importing models: {e}")

print("Starting database initialization...")
with app.app_context():
    print("Creating database tables...")
    models.db.create_all()
    print("Database tables created.")

    # Print the database path
    print(f"Database path: {app.config['SQLALCHEMY_DATABASE_URI']}")

    # Check if tables were created
    inspector = inspect(models.db.engine)
    tables = inspector.get_table_names()
    if tables:
        print(f"Database tables created successfully: {tables}")
    else:
        print("No tables found in the database.")


# Create a user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
  


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
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            if next_page and next_page != url_for('logout'):
                return redirect(next_page)
            else:
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

@app.route('/lehrveranstaltungen')
@login_required
def lehrveranstaltungen():
    lehrveranstaltungen = Lehrveranstaltung.query.all()
    return render_template('lehrveranstaltungen.html', lehrveranstaltungen=lehrveranstaltungen)

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
    return redirect(url_for('login'))