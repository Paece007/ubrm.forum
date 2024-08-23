# app/routes/download.py
from flask import Blueprint, send_from_directory, abort
from flask_login import login_required
import os
from werkzeug.utils import secure_filename
from app import app

download_bp = Blueprint('download', __name__)

@download_bp.route('/download/<filename>')
@login_required
def download_file(filename):
    try:
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            print(f"Upload folder '{app.config['UPLOAD_FOLDER']}' does not exist.")
            abort(500)
        
        filename = secure_filename(filename)
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        print(f"Error: {e}")
        abort(500)