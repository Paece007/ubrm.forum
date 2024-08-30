# Import the configuration
print("Importing configuration...(App)")
from flask import render_template, flash, redirect, url_for, abort, send_from_directory, jsonify, request, make_response, send_file, session
from sqlalchemy import inspect
from flask_login import login_user, login_required, logout_user, current_user
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from datetime import datetime
import urllib.parse
from urllib.parse import unquote
from io import BytesIO
import os
import time
import sys



print("Configuration imported. (App)")

load_dotenv()

from app import create_app, login_manager, db, bcrypt, csrf, cache
from app.models import User, RegisterForm, LoginForm, Lehrveranstaltung, UploadFileForm, Upload, Like, CommentForm, Comment

app = create_app()

app.logger.info("App started successfully.")


app.logger.info("Importing models...(App)")
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

if 'gunicorn' in sys.modules:
        print("Running with Gunicorn")
elif os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    print("Running with Flask development server")
else:
    print(f"Running with an unknown server: {sys.argv[0]}")

# Create a user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
  


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/download/<lehrveranstaltung_id>/<filename>')
@login_required
def download_file(lehrveranstaltung_id, filename):
    
    print("Download request received")
    print("Lehrveranstaltung ID: ", lehrveranstaltung_id)
    print("Filename: ", filename)

    # Ensure the filename is not None
    if filename is None:
        print("Error: Filename is None.")
        abort(404)

    # Query the database for the file
    upload = Upload.query.filter_by(Lehrveranstaltung_id=lehrveranstaltung_id, filename=filename).first()
    

    # Check if the file exists in the database
    if upload is None:
        print("Error: File does not exist in the database.")
        abort(404)

    print("File found in database.")
    
    # Create a BytesIO object from the file data
    file_data = BytesIO(upload.data)

    # Send the file to the client
    response = make_response(send_file(file_data, as_attachment=True, download_name=filename))
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    return response

@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    app.logger.info("Login request received.")
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    app.logger.info("Creating login form.")
    form = LoginForm()

    if request.method == 'POST':
        if form.validate_on_submit():

            user = User.query.filter_by(username=form.username.data).first()
            if user:
                try:
                    if bcrypt.check_password_hash(user.password, form.password.data):

                        app.logger.info("User authenticated.")
                        login_user(user)
                        next_page = request.args.get('next')
                        
                        
                        if next_page and next_page != url_for('logout'):
                            flash('You have been logged in.', 'success')
                            return redirect(next_page)
                        else:
                            flash('You have been logged in.', 'success')
                            return redirect(url_for('dashboard'))
                    else:
                        app.logger.warning("Password check failed for user: %s", user.username)
                        flash('Invalid username or password.', 'danger')
                except ValueError as e:
                    app.logger.error(f"Error during password check: {e}")
                    flash('An error occurred during login. Please try again.', 'danger')
            else:
                app.logger.warning("User not found: %s", form.username.data)
                flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt
def register():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            joined = datetime.now()
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            print(f"Hashed password: {hashed_password}")
            
            if User.query.filter_by(username=username).first():
                flash('Username already exists. Please choose a different one.', 'danger')
                return redirect(url_for('register'))
            
            new_user = User(username=username, password=hashed_password, joined=joined)
            db.session.add(new_user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid input. Please try again.', 'danger')
            return render_template('register.html', form=form)
    return render_template('register.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/profile')
@cache.cached(timeout=60)
@login_required
def profile():
    user = User.query.get(current_user.id)
    uploads = Upload.query.filter_by(uploaded_by=current_user.id).all()
    comments = Comment.query.filter_by(user_id=current_user.id).all()
    likes_received = Like.query.filter_by(user_id=current_user.id).count()
    return render_template('profile.html', user=user, uploads=uploads, comments=comments, likes_received=likes_received)

@app.route('/lehrveranstaltungen')
@cache.cached(timeout=60)
@login_required
def lehrveranstaltungen():
    app.logger.info("Lehrveranstaltungen request received.")
    lehrveranstaltungen = Lehrveranstaltung.query.order_by(Lehrveranstaltung.name).all()
    
    return render_template('lehrveranstaltungen.html', lehrveranstaltungen=lehrveranstaltungen)


@app.route('/lehrveranstaltungen/<encoded_name>', methods=['GET', 'POST'])
@cache.cached(timeout=60)
@login_required
def lv_detail(encoded_name):
    # Decode the URL-encoded name twice
    decoded_name = urllib.parse.unquote(urllib.parse.unquote(encoded_name))
    app.logger.info(f"Encoded name: {encoded_name}")
    app.logger.info(f"Decoded name: {decoded_name}")

    lehrveranstaltung = Lehrveranstaltung.query.filter_by(name=decoded_name).first()
    app.logger.info(lehrveranstaltung.name)
    app.logger.info(lehrveranstaltung.id)
    
    if lehrveranstaltung is None:
        app.logger.error(f"Lehrveranstaltung with name {decoded_name} not found.")
        return "Lehrveranstaltung not found", 404 

    form = UploadFileForm()
    if request.method == 'POST':
        
        # Set the Lehrveranstaltung_id field to the ID of the current Lehrveranstaltung
        lehrveranstaltung_id = Lehrveranstaltung.query.filter_by(name=lehrveranstaltung.name).first().id
        form.Lehrveranstaltung_id.data = lehrveranstaltung_id
        form.uploaded_by.data = current_user.username
        form.upload_date.data = datetime.now()
        if form.validate_on_submit():
            print("Form validated successfully.")
            f = form.file.data
            filename = secure_filename(f.filename)

            file_content = f.read()
            
            # Save upload information to the database
            upload = Upload(
                filename=filename,
                Lehrveranstaltung_id=lehrveranstaltung_id,
                uploaded_by=current_user.id,
                upload_date=datetime.now(),
                data=file_content
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
def delete_comment(comment_id):
    comment = Comment.query.get(comment_id)
    if not comment:
        app.logger.warning(f"Comment with id {comment_id} not found.")
        return jsonify({'error': 'Comment not found'}), 404

    if comment.user_id != current_user.id:
        app.logger.warning(f"Unauthorized delete attempt by user {current_user.id} for comment {comment_id}.")
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        db.session.delete(comment)
        db.session.commit()
        app.logger.info(f"Comment {comment_id} deleted by user {current_user.id}.")
        return jsonify({'success': True}), 200
    except Exception as e:
        app.logger.error(f"Error deleting comment {comment_id}: {e}")
        db.session.rollback()
        return jsonify({'error': 'Internal Server Error'}), 500

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    session.clear()  # Clear the session to remove all session data, including the CSRF token
    cache.clear()
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('csrf_token')  # Clear the session cookie
    flash('You have been logged out.', 'success')
    return response

@app.route('/favicon.ico')
def favicon():
    response = make_response(send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico'))
    print("Setting Cache-Control header to 'public, max-age=86400")
    response.headers['Cache-Control'] = 'public, max-age=86400'  # Cache for 1 day
    print("Cache-Control header set to:", response.headers['Cache-Control'])
    return response
