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
from urllib.parse import unquote
from flask_wtf.csrf import CSRFProtect

import logging

print("Configuration imported. (App)")

load_dotenv()

from app import create_app, login_manager, db, bcrypt, csrf
from app.models import User, RegisterForm, LoginForm, Lehrveranstaltung, UploadFileForm, Upload, Like, CommentForm, Comment

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


@app.route('/download/<lehrveranstaltung_id>/<filename>')
@login_required
def download_file(lehrveranstaltung_id, filename):
    
    print("Download request received")

    print("Lehrveranstaltung ID: ", lehrveranstaltung_id)
    print("Filename: ", filename)

    # Define the directory where files are stored
    upload_directory = os.path.join(app.root_path, 'static', 'files', str(lehrveranstaltung_id))
    
    print("Upload directory: ", upload_directory)
    # Ensure the filename is not None
    if filename is None:
        print("Error: Filename is None.")
        abort(404)
    
    # Construct the full file path
    file_path = os.path.join(upload_directory, filename)
    
    # Check if the file exists
    if not os.path.exists(file_path):
        print("Error: File does not exist.")
        abort(404)
    
    print("File path: ", file_path)
    # Send the file to the client
    return send_from_directory(upload_directory, filename)

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
    lehrveranstaltungen = Lehrveranstaltung.query.order_by(Lehrveranstaltung.name).all()
    return render_template('lehrveranstaltungen.html', lehrveranstaltungen=lehrveranstaltungen)


@app.route('/lehrveranstaltungen/<encoded_name>', methods=['GET', 'POST'])
@login_required
def lv_detail(encoded_name):
    print("Encoded name: ?", encoded_name)
    lehrveranstaltung = Lehrveranstaltung.query.filter_by(name=unquote(encoded_name)).first()
    print(lehrveranstaltung.name)
    print(lehrveranstaltung.id)

    lv_folder = os.path.join(app.config['UPLOAD_FOLDER'],str(lehrveranstaltung.id))
    if not os.path.exists(lv_folder):
        print("Error: Lehrveranstaltung folder does not exist.")
        abort(404)

    form = UploadFileForm()
    #Upload form

    # Set the Lehrveranstaltung_id field to the ID of the current Lehrveranstaltung
    lehrveranstaltung_id = Lehrveranstaltung.query.filter_by(name=lehrveranstaltung.name).first().id
    form.Lehrveranstaltung_id.data = lehrveranstaltung_id
    form.uploaded_by.data = current_user.username
    form.upload_date.data = datetime.now()
    if form.validate_on_submit():
        print("Form validated successfully.")
        f = form.file.data
        filename = secure_filename(f.filename)
        file_path = f.save(os.path.join(lv_folder, filename))
        print(f"File saved to {file_path}")

        # Save upload information to the database
        upload = Upload(
            filename=filename,
            Lehrveranstaltung_id=lehrveranstaltung_id,
            uploaded_by=current_user.id,
            upload_date=datetime.now()
        )
        db.session.add(upload)
        db.session.commit()
        print("Upload saved to the database.")

        flash('File uploaded successfully.', 'success')
        return redirect(url_for('lv_detail', encoded_name=lehrveranstaltung.encoded_name))
    else:
        print("Form validation failed.")
        print(form.errors)  # Print form errors to debug


    uploads = Upload.query.filter_by(Lehrveranstaltung_id=lehrveranstaltung.id).all()
    print(uploads)
    return render_template('lv_detail.html', lehrveranstaltung=lehrveranstaltung, uploads=uploads, form=form)



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


@app.route('/lehrveranstaltungen/<encoded_name>/<upload_id>', methods=['GET', 'POST'])
@login_required
def upload_detail(encoded_name, upload_id):
    lehrveranstaltung = Lehrveranstaltung.query.filter_by(name=unquote(encoded_name)).first()
    upload = Upload.query.get_or_404(upload_id)
    form = CommentForm()
    comments = db.session.query(Comment, User.username).filter(Comment.upload_id == upload_id).join(User, Comment.user_id == User.id).all()
    return render_template('upload_detail.html', lehrveranstaltung=lehrveranstaltung, upload=upload, comments=comments, form=form)

@app.route('/comment/<upload_id>', methods=['POST'])
@login_required
def add_comment(upload_id):
    data = request.get_json()
    content = data.get('content')
    if not content:
        return jsonify({'success': False, 'message': 'Content is required.'}), 400

    comment = Comment(
        content=content,
        upload_id=upload_id,
        user_id=current_user.id,
        upload_date=datetime.now()
    )
    db.session.add(comment)
    db.session.commit()

    return jsonify({
        'success': True,
        'comment': {
            'content': comment.content,
            'upload_date': comment.upload_date.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': current_user.username
        }
    })


@app.route('/delete_comment/<int:comment_id>', methods=['DELETE'])
@login_required
@csrf.exempt  # Ensure CSRF protection is applied globally or use a token in the request
def delete_comment(comment_id):
    comment = Comment.query.get(comment_id)
    if not comment:
        logging.warning(f"Comment with id {comment_id} not found.")
        return jsonify({'error': 'Comment not found'}), 404

    if comment.user_id != current_user.id:
        logging.warning(f"Unauthorized delete attempt by user {current_user.id} for comment {comment_id}.")
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        db.session.delete(comment)
        db.session.commit()
        logging.info(f"Comment {comment_id} deleted by user {current_user.id}.")
        return jsonify({'success': True}), 200
    except Exception as e:
        logging.error(f"Error deleting comment {comment_id}: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))