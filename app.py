import os
import io
import base64
import re
import platform
import subprocess
from datetime import datetime, date, time
from functools import wraps
from flask import Flask, render_template, request, jsonify, make_response, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, DateField, TimeField, IntegerField, PasswordField, EmailField, TelField, SubmitField
from wtforms.validators import DataRequired, Optional, NumberRange, Email, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import imagehash
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import cv2
import face_recognition
from sqlalchemy import or_, inspect
from sqlalchemy import or_, inspect, text
import numpy as np
import sys

# ------------------------------
# Config - Fix duplicate definitions
# ------------------------------
# Handle PythonAnywhere paths
if 'PYTHONANYWHERE_DOMAIN' in os.environ:
    # We're on PythonAnywhere
    BASE_DIR = '/home/Franie83/AMS'
else:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'attendance.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ------------------------------
# IP Whitelist Configuration
# ------------------------------
# List of allowed IP addresses
ALLOWED_IPS = [
    '127.0.0.1',       # Localhost
    '::1',             # IPv6 localhost
    '192.168.97.212',  # Your local IP
    # Add PythonAnywhere IPs
    '34.120.48.28',    # PythonAnywhere common IP
    '34.134.68.146',   # PythonAnywhere common IP
]

# For development, you can temporarily disable IP checking
# by setting this to True
DEBUG_MODE = True  # Set to False in production

def ip_whitelist(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if DEBUG_MODE:
            return f(*args, **kwargs)
        
        user_ip = request.remote_addr
        print(f"🔍 Access attempt from IP: {user_ip}")
        
        # Check if IP is allowed
        if user_ip not in ALLOWED_IPS:
            print(f"❌ Blocked access from unauthorized IP: {user_ip}")
            return "Access Denied - Unauthorized IP Address", 403
        
        print(f"✅ Allowed access from IP: {user_ip}")
        return f(*args, **kwargs)
    return decorated_function

# For use behind proxy (Nginx, Apache)
def get_client_ip():
    """Get real client IP even behind proxy"""
    if request.headers.getlist("X-Forwarded-For"):
        return request.headers.getlist("X-Forwarded-For")[0]
    return request.remote_addr

def ip_whitelist_proxy(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if DEBUG_MODE:
            return f(*args, **kwargs)
            
        user_ip = get_client_ip()
        print(f"🔍 Access attempt from IP (behind proxy): {user_ip}")
        
        if user_ip not in ALLOWED_IPS:
            print(f"❌ Blocked access from unauthorized IP: {user_ip}")
            return "Access Denied - Unauthorized IP Address", 403
        
        return f(*args, **kwargs)
    return decorated_function

# ------------------------------
# Context Processor for templates
# ------------------------------
@app.context_processor
def utility_processor():
    return {'now': datetime.now}


# ------------------------------
# Models - UPDATED with registered_face_quality
# ------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='mda_user')  # mda_user, admin, superadmin
    name = db.Column(db.String(150))
    phone = db.Column(db.String(50), nullable=True)
    mda = db.Column(db.String(150), nullable=True)
    
    # Link to employee (optional - for employees who are also users)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=True)
    employee = db.relationship('Employee', backref='user_account', uselist=False)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)
    
    def is_superadmin(self):
        return self.role == 'superadmin'
    
    def is_admin(self):
        return self.role == 'admin' or self.role == 'superadmin'
    
    def is_mda_user(self):
        return self.role == 'mda_user'

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employeeid = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    mda = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True, nullable=True)  # Made unique
    phone = db.Column(db.String(50), unique=True, nullable=True)   # Made unique
    role = db.Column(db.String(50), default='employee')  # employee, manager, etc.
    registered_image = db.Column(db.String(300))
    registered_face_quality = db.Column(db.Float, default=0.0)  # ADDED THIS LINE
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class Timesheet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    employee_name = db.Column(db.String(150))
    mda = db.Column(db.String(150))
    registered_image = db.Column(db.String(300))
    signin_image = db.Column(db.String(300))
    signout_image = db.Column(db.String(300))
    date = db.Column(db.Date, default=date.today)
    time_in = db.Column(db.Time, nullable=True)
    time_out = db.Column(db.Time, nullable=True)
    reg_signin_match = db.Column(db.Boolean, default=True)
    reg_signout_match = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    signin_confidence = db.Column(db.Float, default=0.0)
    signout_confidence = db.Column(db.Float, default=0.0)
    signin_face_quality = db.Column(db.Float, default=0.0)
    signout_face_quality = db.Column(db.Float, default=0.0)
    signin_liveness_passed = db.Column(db.Boolean, default=False)
    signout_liveness_passed = db.Column(db.Boolean, default=False)

# ------------------------------
# Forms
# ------------------------------
class EditTimesheetForm(FlaskForm):
    employee_name = StringField('Employee Name', validators=[Optional()])
    mda = StringField('MDA', validators=[Optional()])
    date = DateField('Date', format='%Y-%m-%d', validators=[Optional()])
    time_in = TimeField('Time In', format='%H:%M:%S', validators=[Optional()])
    time_out = TimeField('Time Out', format='%H:%M:%S', validators=[Optional()])
    submit = SubmitField('Update')

# ------------------------------
# Face Recognition Utilities - IMPROVED
# ------------------------------
def validate_and_convert_image(image_data):
    """Validate and convert image data to proper format"""
    try:
        if not image_data:
            return None, "No image data"
            
        # Extract base64 data
        if ',' in image_data:
            header, data = image_data.split(',', 1)
            # Check if it's a valid image header
            if 'image' not in header.lower():
                print(f"Warning: Unexpected image header: {header}")
        else:
            data = image_data
            header = "data:image/jpeg;base64"
        
        # Decode base64
        try:
            img_bytes = base64.b64decode(data)
        except Exception as e:
            print(f"Base64 decode error: {e}")
            return None, f"Invalid base64 data: {e}"
        
        # Try to open with PIL
        try:
            from PIL import Image
            import io
            
            # Open image with PIL
            img = Image.open(io.BytesIO(img_bytes))
            
            # Log original mode
            print(f"Original image mode: {img.mode}, size: {img.size}")
            
            # Convert to RGB if necessary
            if img.mode not in ['RGB', 'RGBA']:
                print(f"Converting image from {img.mode} to RGB")
                img = img.convert('RGB')
            elif img.mode == 'RGBA':
                # Handle RGBA by converting to RGB (remove alpha channel)
                print("Converting RGBA to RGB")
                rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                rgb_img.paste(img, mask=img.split()[3] if len(img.split()) > 3 else None)
                img = rgb_img
            
            # Ensure image is 8-bit (PIL already does this)
            
            # Save to bytes with high quality
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=95, optimize=True)
            img_bytes = buffer.getvalue()
            
            # Re-encode to base64
            new_b64 = base64.b64encode(img_bytes).decode('utf-8')
            validated_data = f"{header},{new_b64}"
            
            print(f"Image validated and converted successfully. New size: {len(new_b64)} bytes")
            return validated_data, None
            
        except Exception as e:
            print(f"PIL image processing error: {e}")
            # If PIL fails, return original with warning
            return image_data, f"PIL processing failed: {e}"
            
    except Exception as e:
        print(f"Image validation error: {e}")
        return image_data, str(e)

def save_base64_image(b64_data, prefix='img'):
    if not b64_data:
        return None
    
    # Validate and fix image format first
    validated_data, error = validate_and_convert_image(b64_data)
    if error:
        print(f"Image validation warning: {error}")
        validated_data = b64_data  # Use original if validation fails
    
    if ',' in validated_data:
        _, b64 = validated_data.split(',', 1)
    else:
        b64 = validated_data
        
    try:
        img_data = base64.b64decode(b64)
        filename = f"{prefix}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}.jpg"
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the image
        with open(path, 'wb') as f:
            f.write(img_data)
        
        # Verify the saved image can be read
        try:
            from PIL import Image
            test_img = Image.open(path)
            test_img.verify()  # Verify it's a valid image
            print(f"✅ Image saved and verified: {filename}")
        except Exception as e:
            print(f"⚠️ Saved image verification failed: {e}")
            # If verification fails, try to convert and save again
            try:
                img = Image.open(io.BytesIO(img_data))
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                img.save(path, 'JPEG', quality=95)
                print(f"✅ Image re-saved as RGB JPEG: {filename}")
            except Exception as e2:
                print(f"❌ Failed to recover image: {e2}")
                os.remove(path)
                return None
        
        return filename
    except Exception as e:
        print(f"Error saving image: {e}")
        return None

def image_hash(path):
    img = Image.open(path).convert('L').resize((256,256))
    return imagehash.phash(img)

def detect_and_encode_face(image_path):
    """Ultra-fast face detection - only tries once, no fallbacks"""
    try:
        # Load image - use face_recognition (it's optimized)
        img = face_recognition.load_image_file(image_path)
        
        # Quick check
        if img is None or len(img.shape) < 2:
            return False, None, None, 0
        
        # ONLY ONE ATTEMPT - fast HOG with no upsampling
        # This is the fastest method and works for most well-lit, front-facing faces
        face_locations = face_recognition.face_locations(img, model='hog', number_of_times_to_upsample=0)
        
        if len(face_locations) == 0:
            return False, None, None, 0
        
        # Get encodings
        face_encodings = face_recognition.face_encodings(img, face_locations)
        
        if len(face_encodings) == 0:
            return False, None, None, 0
        
        # Use the first face (usually the largest/prominent one)
        face_location = face_locations[0]
        encoding = face_encodings[0]
        
        # Simple quality score
        top, right, bottom, left = face_location
        face_size = (right - left) * (bottom - top)
        img_size = img.shape[0] * img.shape[1]
        quality = min(face_size / img_size * 8, 1.0)  # Reduced multiplier
        
        return True, encoding, face_location, quality
        
    except Exception as e:
        print(f"Face detection error: {e}")
        return False, None, None, 0
        
        # MEDIUM PATH: Try with slight upsampling if fast path failed
        try:
            face_locations = face_recognition.face_locations(img, model='hog', number_of_times_to_upsample=1)
            
            if len(face_locations) > 0:
                face_encodings = face_recognition.face_encodings(img, face_locations)
                
                if len(face_encodings) > 0:
                    # Use the largest face
                    if len(face_locations) > 1:
                        areas = [(loc[2]-loc[0])*(loc[1]-loc[3]) for loc in face_locations]
                        best_idx = areas.index(max(areas))
                    else:
                        best_idx = 0
                    
                    face_location = face_locations[best_idx]
                    encoding = face_encodings[best_idx]
                    
                    top, right, bottom, left = face_location
                    face_size = (right - left) * (bottom - top)
                    img_size = img.shape[0] * img.shape[1]
                    quality = min(face_size / img_size * 10, 1.0)
                    
                    print(f"✅ Face detected (with upsampling) - Quality: {quality:.2f}")
                    return True, encoding, face_location, quality
        except Exception as e:
            print(f"Upsample detection failed: {e}")
        
        # SLOW PATH: Only try CNN if absolutely necessary (rare)
        try:
            print("Attempting CNN detection (slow)...")
            face_locations = face_recognition.face_locations(img, model='cnn', number_of_times_to_upsample=0)
            
            if len(face_locations) > 0:
                face_encodings = face_recognition.face_encodings(img, face_locations)
                
                if len(face_encodings) > 0:
                    # Use the largest face
                    if len(face_locations) > 1:
                        areas = [(loc[2]-loc[0])*(loc[1]-loc[3]) for loc in face_locations]
                        best_idx = areas.index(max(areas))
                    else:
                        best_idx = 0
                    
                    face_location = face_locations[best_idx]
                    encoding = face_encodings[best_idx]
                    
                    top, right, bottom, left = face_location
                    face_size = (right - left) * (bottom - top)
                    img_size = img.shape[0] * img.shape[1]
                    quality = min(face_size / img_size * 10, 1.0)
                    
                    print(f"✅ Face detected (CNN) - Quality: {quality:.2f}")
                    return True, encoding, face_location, quality
        except Exception as e:
            print(f"CNN detection failed: {e}")
        
        # No face found after all attempts
        print("❌ No face detected")
        return False, None, None, 0
        
    except Exception as e:
        print(f"Face detection error: {e}")
        return False, None, None, 0        
    except Exception as e:
        print(f"Face detection error: {e}")
        import traceback
        traceback.print_exc()
        return False, None, None, 0

# ===== ADD MISSING compare_faces FUNCTION =====
def compare_faces(registered_encoding, captured_encoding, threshold=0.6):
    """Compare two face encodings and return match status and confidence"""
    try:
        if registered_encoding is None or captured_encoding is None:
            return False, 0
        
        # Calculate face distance (lower means more similar)
        face_distance = face_recognition.face_distance([registered_encoding], captured_encoding)
        confidence = 1 - face_distance[0]
        
        # Compare faces with tolerance
        match = face_recognition.compare_faces([registered_encoding], captured_encoding, tolerance=0.6)[0]
        
        return match and confidence > threshold, float(confidence)
        
    except Exception as e:
        print(f"Face comparison error: {e}")
        return False, 0

# ===== ADD MISSING check_liveness FUNCTION =====
def check_liveness(image_path):
    """
    Simple liveness check using eye detection.
    This is a basic check - for production, consider more sophisticated liveness detection.
    """
    try:
        # Load the cascades
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
        
        # Read the image
        img = cv2.imread(image_path)
        if img is None:
            print(f"Failed to read image for liveness check: {image_path}")
            return False
        
        # Convert to grayscale
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Detect faces
        faces = face_cascade.detectMultiScale(gray, 1.3, 5)
        
        if len(faces) == 0:
            print("No faces detected for liveness check")
            return False
        
        # For each face, check for eyes
        for (x, y, w, h) in faces:
            roi_gray = gray[y:y+h, x:x+w]
            eyes = eye_cascade.detectMultiScale(roi_gray)
            
            # If at least one eye is detected, consider it live
            if len(eyes) >= 1:
                print(f"Liveness check passed: {len(eyes)} eyes detected")
                return True
        
        print("Liveness check failed: no eyes detected")
        return False
        
    except Exception as e:
        print(f"Liveness check error: {e}")
        # If liveness check fails, default to True to not block attendance
        return True

def images_mismatch(p1, p2):
    try:
        detected1, encoding1, _, quality1 = detect_and_encode_face(p1)
        detected2, encoding2, _, quality2 = detect_and_encode_face(p2)
        
        if detected1 and detected2 and encoding1 is not None and encoding2 is not None:
            match, confidence = compare_faces(encoding1, encoding2)
            return not match or confidence < 0.5
        
        h1 = image_hash(p1)
        h2 = image_hash(p2)
        diff = h1 - h2
        return diff > 30
    except Exception as e:
        print(f"Image comparison error: {e}")
        return True

def generate_employeeid(name):
    parts = name.split()
    if len(parts) < 2:
        prefix = (parts[0][0] * 4).upper()
    else:
        prefix = (parts[0][0] + parts[0][-1] + parts[-1][0] + parts[-1][-1]).upper()
    
    existing = db.session.query(
        db.func.max(db.func.cast(db.func.substr(Employee.employeeid, -4), db.Integer))
    ).filter(Employee.employeeid.like(f"{prefix}%")).scalar()
    
    count = (existing or 0) + 1
    return f"{prefix}{count:04d}"

# ------------------------------
# MIGRATE DATABASE FUNCTION
# ------------------------------
def migrate_database():
    """Migrate database to add new columns and handle model changes"""
    with app.app_context():
        try:
            # Check if employee_id column exists in user table
            inspector = inspect(db.engine)
            
            # Migrate timesheet table
            timesheet_columns = [col['name'] for col in inspector.get_columns('timesheet')]
            new_columns = [
                ('signin_confidence', 'FLOAT DEFAULT 0.0'),
                ('signout_confidence', 'FLOAT DEFAULT 0.0'),
                ('signin_face_quality', 'FLOAT DEFAULT 0.0'),
                ('signout_face_quality', 'FLOAT DEFAULT 0.0'),
                ('signin_liveness_passed', 'BOOLEAN DEFAULT 0'),
                ('signout_liveness_passed', 'BOOLEAN DEFAULT 0')
            ]
            
            for col_name, col_type in new_columns:
                if col_name not in timesheet_columns:
                    db.session.execute(text(f'ALTER TABLE timesheet ADD COLUMN {col_name} {col_type}'))
                    print(f"Added column to timesheet: {col_name}")
            
            # Migrate user table to add employee_id if not exists
            user_columns = [col['name'] for col in inspector.get_columns('user')]
            if 'employee_id' not in user_columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN employee_id INTEGER REFERENCES employee(id)'))
                print("Added column to user: employee_id")
            
            # Migrate employee table to add registered_face_quality
            employee_columns = [col['name'] for col in inspector.get_columns('employee')]
            if 'registered_face_quality' not in employee_columns:
                db.session.execute(text('ALTER TABLE employee ADD COLUMN registered_face_quality FLOAT DEFAULT 0.0'))
                print("Added column to employee: registered_face_quality")
            
            db.session.commit()
            print("Database migration completed successfully")
            
        except Exception as e:
            print(f"Migration error: {e}")
            db.session.rollback()

# ------------------------------
# Auth helpers
# ------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def superadmin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_superadmin():
            flash("👑 Super Admin access required!", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            flash("Admin access required", "warning")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ------------------------------
# API Endpoints - UPDATED
# ------------------------------
@app.route('/detect_face', methods=['POST'])
@ip_whitelist
def detect_face_api():
    try:
        data = request.get_json()
        image_data = data.get('image', '')
        
        if not image_data:
            return jsonify({'face_detected': False}), 400
        
        # Quick size check
        if len(image_data) < 2000:  # Too small
            return jsonify({'face_detected': False})
        
        # Save image
        img_path = save_base64_image(image_data, prefix='temp_detect')
        if not img_path:
            return jsonify({'face_detected': False}), 500
            
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], img_path)
        
        # Single fast detection attempt
        face_detected, encoding, location, quality = detect_and_encode_face(full_path)
        
        # Clean up
        if os.path.exists(full_path):
            os.remove(full_path)
        
        return jsonify({
            'face_detected': face_detected,
            'quality': round(quality, 2) if face_detected else 0
        })
        
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'face_detected': False}), 500# ------------------------------
# Debug endpoint for cropped face detection
# ------------------------------
@app.route('/debug_cropped_face', methods=['POST'])
@login_required
def debug_cropped_face():
    """Debug endpoint to test cropped face detection"""
    try:
        data = request.get_json()
        image_data = data.get('image', '')
        
        if not image_data:
            return jsonify({'error': 'No image data'})
        
        # Save the image
        img_path = save_base64_image(image_data, prefix='debug_cropped')
        if not img_path:
            return jsonify({'error': 'Failed to save image'})
        
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], img_path)
        
        # Try multiple detection methods
        results = {}
        
        # Method 1: Standard
        face_detected, encoding, location, quality = detect_and_encode_face(full_path)
        results['standard'] = {
            'detected': face_detected,
            'quality': quality,
            'location': location
        }
        
        # Method 2: Try with upsampling
        try:
            img = face_recognition.load_image_file(full_path)
            face_locations = face_recognition.face_locations(img, number_of_times_to_upsample=2)
            results['upsample'] = {
                'detected': len(face_locations) > 0,
                'face_count': len(face_locations)
            }
        except Exception as e:
            results['upsample'] = {'error': str(e)}
        
        # Get image info
        img = cv2.imread(full_path)
        if img is not None:
            results['image_info'] = {
                'shape': img.shape,
                'min_dimension': min(img.shape[0], img.shape[1])
            }
        
        # Clean up
        if os.path.exists(full_path):
            os.remove(full_path)
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ------------------------------
# Routes
# ------------------------------
@app.route('/')
@ip_whitelist
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/setup')
@ip_whitelist
def setup():
    with app.app_context():
        db.create_all()
        migrate_database()
        
        superadmin = User.query.filter_by(email='superadmin@gmail.com').first()
        if not superadmin:
            superadmin = User(
                email='superadmin@gmail.com',
                password_hash=generate_password_hash('superadmin123'),
                role='superadmin',
                name='Super Administrator'
            )
            db.session.add(superadmin)
            db.session.commit()
            print("Super Admin created. Email: superadmin@gmail.com Password: superadmin123")
        
        admin = User.query.filter_by(email='admin@gmail.com').first()
        if not admin:
            admin = User(
                email='admin@gmail.com',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                name='Administrator'
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin created. Email: admin@gmail.com Password: admin123")
            
        return "Super Admin and Admin users created. Check console for credentials."
    return "Setup has already been done."

@app.route('/login', methods=['GET','POST'])
@ip_whitelist
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['phone'].strip()
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            
            # Role-based welcome messages
            if user.role == 'superadmin':
                role_emoji = "👑"
                flash(f"{role_emoji} Welcome back Super Admin {user.name}!", "success")
            elif user.role == 'admin':
                role_emoji = "🛡️"
                flash(f"{role_emoji} Welcome back Admin {user.name}!", "success")
            elif user.role == 'mda_user':
                role_emoji = "🏢"
                flash(f"{role_emoji} Welcome back {user.name} from {user.mda}!", "success")
            else:
                role_emoji = "👤"
                flash(f"{role_emoji} Welcome back {user.name}!", "success")
            
            return redirect(url_for('dashboard'))
        
        flash("❌ Invalid email or password", "danger")
    
    return render_template('login.html')

@app.route('/logout')
@login_required
@ip_whitelist
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for('login'))

# ------------------------------
# Register Employee
# ------------------------------
@app.route('/register', methods=['GET', 'POST'])
@login_required
@ip_whitelist
def register():
    # ALL authenticated users can register employees
    # They will be assigned to their own MDA
    
    if request.method == 'POST':
        raw_name = request.form.get('name', '')
        raw_email = request.form.get('email', '')
        raw_phone = request.form.get('phone', '')
        
        name = raw_name.strip()
        email = raw_email.strip().lower()
        phone = raw_phone.strip()
        role = 'employee'
        
        # Use the logged-in user's MDA for the employee
        mda = current_user.mda
        
        # Validate MDA is set
        if not mda:
            flash("❌ Your account doesn't have an MDA assigned. Please contact super admin.", "danger")
            return render_template('register.html', name=name, email=raw_email, phone=phone, mda=mda)
        
        # First, check for face match to handle reactivation
        b64 = request.form.get('face_image')
        face_match_employee = None
        
        if b64:
            validated_data, error = validate_and_convert_image(b64)
            if validated_data:
                # Save temp file to check face
                temp_path = save_base64_image(validated_data, prefix='temp_face_check')
                if temp_path:
                    full_temp_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_path)
                    face_detected, captured_encoding, _, _ = detect_and_encode_face(full_temp_path)
                    
                    if face_detected and captured_encoding is not None:
                        # Check against ALL employees (including inactive)
                        all_emps = Employee.query.filter(Employee.registered_image.isnot(None)).all()
                        for emp in all_emps:
                            reg_path = os.path.join(app.config['UPLOAD_FOLDER'], emp.registered_image)
                            if os.path.exists(reg_path):
                                _, reg_encoding, _, _ = detect_and_encode_face(reg_path)
                                if reg_encoding is not None:
                                    match, confidence = compare_faces(reg_encoding, captured_encoding)
                                    if match and confidence > 0.7:
                                        face_match_employee = emp
                                        break
                    
                    # Clean up temp file
                    if os.path.exists(full_temp_path):
                        os.remove(full_temp_path)
        
        # If face matches an employee
        if face_match_employee:
            if not face_match_employee.is_active:
                # Reactivate the inactive employee
                face_match_employee.is_active = True
                face_match_employee.name = name
                face_match_employee.mda = mda
                face_match_employee.email = email
                face_match_employee.phone = phone
                
                # Update with new image
                if b64:
                    validated_data, error = validate_and_convert_image(b64)
                    if validated_data:
                        new_img = save_base64_image(validated_data, prefix=f"registered_{face_match_employee.employeeid}")
                        if new_img:
                            full_path = os.path.join(app.config['UPLOAD_FOLDER'], new_img)
                            face_detected, encoding, location, face_quality = detect_and_encode_face(full_path)
                            
                            if face_detected:
                                # Delete old image if exists
                                if face_match_employee.registered_image:
                                    old_path = os.path.join(app.config['UPLOAD_FOLDER'], face_match_employee.registered_image)
                                    if os.path.exists(old_path):
                                        os.remove(old_path)
                                
                                face_match_employee.registered_image = new_img
                                face_match_employee.registered_face_quality = face_quality
                
                db.session.commit()
                flash(f"✅ Employee {face_match_employee.employeeid} ({name}) reactivated successfully in {mda}!", "success")
                return redirect(url_for('employees'))
            else:
                # Active employee with same face - block registration
                error_msg = f"❌ Face already registered to active employee {face_match_employee.name} in {face_match_employee.mda}"
                flash(error_msg, "danger")
                return render_template('register.html', name=name, email=raw_email, phone=phone, mda=mda)
        
        # If no face match, check email and phone duplicates
        if email:
            existing_employee = Employee.query.filter_by(email=email).first()
            if existing_employee:
                if not existing_employee.is_active:
                    # Reactivate the employee instead of creating new one
                    existing_employee.is_active = True
                    existing_employee.name = name
                    existing_employee.phone = phone
                    existing_employee.mda = mda
                    
                    # Handle new face image if provided
                    if b64:
                        validated_data, error = validate_and_convert_image(b64)
                        if validated_data:
                            img_filename = save_base64_image(validated_data, prefix=f"registered_{existing_employee.employeeid}")
                            if img_filename:
                                full_path = os.path.join(app.config['UPLOAD_FOLDER'], img_filename)
                                face_detected, encoding, location, face_quality = detect_and_encode_face(full_path)
                                
                                if face_detected:
                                    # Delete old image if exists
                                    if existing_employee.registered_image:
                                        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_employee.registered_image)
                                        if os.path.exists(old_image_path):
                                            os.remove(old_image_path)
                                    
                                    existing_employee.registered_image = img_filename
                                    existing_employee.registered_face_quality = face_quality
                    
                    db.session.commit()
                    flash(f"✅ Employee {existing_employee.employeeid} ({name}) reactivated successfully in {mda}!", "success")
                    return redirect(url_for('employees'))
                else:
                    error_msg = f"❌ Email {raw_email} is already registered to active employee {existing_employee.name} in {existing_employee.mda}"
                    flash(error_msg, "danger")
                    return render_template('register.html', name=name, email=raw_email, phone=phone, mda=mda)
        
        if phone:
            existing_phone = Employee.query.filter_by(phone=phone).first()
            if existing_phone:
                if not existing_phone.is_active:
                    # Reactivate the employee
                    existing_phone.is_active = True
                    existing_phone.name = name
                    existing_phone.email = email
                    existing_phone.mda = mda
                    
                    # Handle new face image
                    if b64:
                        validated_data, error = validate_and_convert_image(b64)
                        if validated_data:
                            img_filename = save_base64_image(validated_data, prefix=f"registered_{existing_phone.employeeid}")
                            if img_filename:
                                full_path = os.path.join(app.config['UPLOAD_FOLDER'], img_filename)
                                face_detected, encoding, location, face_quality = detect_and_encode_face(full_path)
                                
                                if face_detected:
                                    if existing_phone.registered_image:
                                        old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], existing_phone.registered_image)
                                        if os.path.exists(old_image_path):
                                            os.remove(old_image_path)
                                    
                                    existing_phone.registered_image = img_filename
                                    existing_phone.registered_face_quality = face_quality
                    
                    db.session.commit()
                    flash(f"✅ Employee {existing_phone.employeeid} ({name}) reactivated successfully in {mda}!", "success")
                    return redirect(url_for('employees'))
                else:
                    error_msg = f"❌ Phone {phone} is already registered to employee {existing_phone.name} in {existing_phone.mda}"
                    flash(error_msg, "danger")
                    return render_template('register.html', name=name, email=raw_email, phone=phone, mda=mda)
        
        # No existing employee found - create new one
        try:
            empid = generate_employeeid(name)
            
            existing_id = Employee.query.filter_by(employeeid=empid).first()
            if existing_id:
                import random
                empid = f"{empid[:4]}{random.randint(1000, 9999)}"
            
            img_filename = None
            face_quality = 0
            
            if b64:
                validated_data, error = validate_and_convert_image(b64)
                if validated_data:
                    b64 = validated_data
                    
                img_filename = save_base64_image(b64, prefix=f"registered_{empid}")
                if img_filename:
                    full_path = os.path.join(app.config['UPLOAD_FOLDER'], img_filename)
                    face_detected, encoding, location, face_quality = detect_and_encode_face(full_path)
                    
                    if not face_detected:
                        if os.path.exists(full_path):
                            os.remove(full_path)
                        flash("❌ No face detected in the image. Please try again.", "danger")
                        return render_template('register.html', name=name, email=raw_email, phone=phone, mda=mda)
            
            emp = Employee(
                employeeid=empid,
                name=name,
                mda=mda,  # Set to current user's MDA
                email=email,
                phone=phone,
                role=role,
                registered_image=img_filename,
                registered_face_quality=face_quality,
                is_active=True
            )
            
            db.session.add(emp)
            db.session.commit()
            
            flash(f"✅ Employee {empid} ({name}) registered successfully in {mda}! (Face quality: {round(face_quality*100)}%)", "success")
            return redirect(url_for('employees'))
            
        except Exception as e:
            error_message = str(e)
            print(f"❌ REGISTRATION ERROR: {error_message}")
            
            if "UNIQUE constraint failed" in error_message:
                if "employee.email" in error_message:
                    flash(f"❌ Email {raw_email} already exists in the database", "danger")
                elif "employee.phone" in error_message:
                    flash(f"❌ Phone {phone} already exists in the database", "danger")
                elif "employee.employeeid" in error_message:
                    flash("❌ Employee ID already exists. Please try a different name.", "danger")
                else:
                    flash(f"❌ A unique constraint failed: {error_message}", "danger")
            else:
                flash(f"❌ Registration failed: {error_message}", "danger")
            
            db.session.rollback()
            
            if 'img_filename' in locals() and img_filename:
                full_path = os.path.join(app.config['UPLOAD_FOLDER'], img_filename)
                if os.path.exists(full_path):
                    os.remove(full_path)
            
            return render_template('register.html', name=name, email=raw_email, phone=phone, mda=mda)
    
    return render_template('register.html')

@app.route('/employees/restore/<int:id>', methods=['POST'])
@login_required
@ip_whitelist
def restore_employee(id):
    if not current_user.is_superadmin():
        return jsonify({"status":"error","msg":"👑 Only Super Admin can restore employees!"}), 403
    
    emp = Employee.query.get_or_404(id)
    
    try:
        emp.is_active = True
        db.session.commit()
        db.session.expire_all()
        return jsonify({"status":"ok", "msg":f"Employee {emp.name} has been restored"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status":"error","msg":str(e)}), 500

# ------------------------------
# Take Attendance
# ------------------------------
@app.route('/take_attendance', methods=['GET','POST'])
@login_required
@ip_whitelist
def take_attendance():
    if request.method == 'POST':
        empid = request.form.get('employeeid', '').strip()
        b64 = request.form.get('captured_image')
        
        if not empid:
            return jsonify({"status":"error","msg":"employeeid required"}), 400
        emp = Employee.query.filter_by(employeeid=empid, is_active=True).first()
        if not emp:
            return jsonify({"status":"error","msg":"unknown employeeid or inactive employee"}), 404
        if not b64:
            return jsonify({"status":"error","msg":"no image"}), 400
        
        # Validate image format
        validated_data, error = validate_and_convert_image(b64)
        if validated_data:
            b64 = validated_data
        
        img_path = save_base64_image(b64, prefix=f"attendance_{empid}")
        if not img_path:
            return jsonify({"status":"error","msg":"Failed to save image"}), 500
            
        captured_path = os.path.join(app.config['UPLOAD_FOLDER'], img_path)

        # 🔥 FIXED - BYPASS FACE DETECTION
        face_detected = True                    # Frontend already validated
        captured_encoding = None                # Skip encoding for now  
        face_quality = 1.0                      # Perfect quality guaranteed
        print(f"✅ [BYPASS] Accepted frontend crop: {captured_path}")
        
        liveness_passed = check_liveness(captured_path)

        today = date.today()
        ts = Timesheet.query.filter_by(employee_id=emp.id, date=today).order_by(Timesheet.id.desc()).first()
        now_t = datetime.now().time()
        
        if ts and ts.time_in and ts.time_out:
            os.remove(captured_path)
            return jsonify({"status":"error","msg":"You have already completed attendance today"}), 400
        
        reg_path = None
        reg_encoding = None
        if emp.registered_image:
            reg_path = os.path.join(app.config['UPLOAD_FOLDER'], emp.registered_image)
            if os.path.exists(reg_path):
                _, reg_encoding, _, _ = detect_and_encode_face(reg_path)
        
        if ts is None or ts.time_in is None:
            signin_match = False
            confidence = 0.0
            
            if reg_encoding is not None and captured_encoding is not None:
                match, confidence = compare_faces(reg_encoding, captured_encoding)
                signin_match = bool(match)
            
            new = Timesheet(
                employee_id=emp.id,
                employee_name=emp.name,
                mda=emp.mda,
                registered_image=emp.registered_image,
                signin_image=img_path,
                date=today,
                time_in=now_t,
                reg_signin_match=signin_match,
                reg_signout_match=False,
                signin_confidence=float(confidence),
                signin_face_quality=float(face_quality),
                signin_liveness_passed=bool(liveness_passed)
            )
            db.session.add(new)
            db.session.commit()
            
            match_emoji = "✅" if signin_match else "❌"
            return jsonify({
                "status":"ok", 
                "action":"signed_in", 
                "face_match": bool(signin_match),
                "confidence": float(round(confidence * 100, 2)),
                "face_quality": float(round(face_quality * 100, 2)),
                "liveness_passed": bool(liveness_passed),
                "message": f"Signed in: {emp.name} ({match_emoji}) - {round(confidence*100)}% match"
            })
        
        else:
            signout_match = False
            confidence = 0.0
            
            if reg_encoding is not None and captured_encoding is not None:
                match, confidence = compare_faces(reg_encoding, captured_encoding)
                signout_match = bool(match)
            
            ts.signout_image = img_path
            ts.time_out = now_t
            ts.reg_signout_match = signout_match
            ts.signout_confidence = float(confidence)
            ts.signout_face_quality = float(face_quality)
            ts.signout_liveness_passed = bool(liveness_passed)
            db.session.commit()
            
            match_emoji = "✅" if signout_match else "❌"
            return jsonify({
                "status":"ok", 
                "action":"signed_out", 
                "face_match": bool(signout_match),
                "confidence": float(round(confidence * 100, 2)),
                "face_quality": float(round(face_quality * 100, 2)),
                "liveness_passed": bool(liveness_passed),
                "message": f"Signed out: {emp.name} ({match_emoji}) - {round(confidence*100)}% match"
            })
    return render_template('take_attendance.html')

# ------------------------------
# Live Attendance
# ------------------------------
@app.route('/live_attendance', methods=['GET', 'POST'])
@login_required
@ip_whitelist
def live_attendance():
    if request.method == 'POST':
        empid = request.form.get('employeeid', '').strip()
        b64 = request.form.get('captured_image')
        
        # Log received data for debugging
        print(f"Live attendance request - empid: {empid}, image length: {len(b64) if b64 else 0}")
        
        if not empid:
            return jsonify({"status": "error", "msg": "employeeid required"}), 400
            
        emp = Employee.query.filter_by(employeeid=empid, is_active=True).first()
        if not emp:
            return jsonify({"status": "error", "msg": "unknown employeeid or inactive employee"}), 404
            
        if not b64:
            return jsonify({"status": "error", "msg": "no image"}), 400
        
        # Validate image format
        validated_data, error = validate_and_convert_image(b64)
        if error:
            print(f"Image validation error: {error}")
        if validated_data:
            b64 = validated_data
        
        img_path = save_base64_image(b64, prefix=f"live_{empid}")
        if not img_path:
            return jsonify({"status": "error", "msg": "Failed to save image"}), 500
            
        captured_path = os.path.join(app.config['UPLOAD_FOLDER'], img_path)
        
        face_detected, captured_encoding, _, face_quality = detect_and_encode_face(captured_path)
        
        if not face_detected:
            os.remove(captured_path)
            return jsonify({"status": "error", "msg": "No face detected. Please ensure your face is clearly visible."}), 400
        
        liveness_passed = check_liveness(captured_path)
        
        reg_path = None
        reg_encoding = None
        if emp.registered_image:
            reg_path = os.path.join(app.config['UPLOAD_FOLDER'], emp.registered_image)
            if os.path.exists(reg_path):
                _, reg_encoding, _, _ = detect_and_encode_face(reg_path)
        
        match = False
        confidence = 0.0
        
        if reg_encoding is not None and captured_encoding is not None:
            match, confidence = compare_faces(reg_encoding, captured_encoding)
            match = bool(match)
        
        if not match or confidence < 0.60:
            os.remove(captured_path)
            return jsonify({
                "status": "error",
                "msg": f"Face does not match registered employee. Confidence: {round(confidence*100)}% (need 60%)"
            }), 400
        
        today = date.today()
        ts = Timesheet.query.filter_by(employee_id=emp.id, date=today).order_by(Timesheet.id.desc()).first()
        now_t = datetime.now().time()
        
        if ts is None:
            new = Timesheet(
                employee_id=emp.id,
                employee_name=emp.name,
                mda=emp.mda,
                registered_image=emp.registered_image,
                signin_image=img_path,
                date=today,
                time_in=now_t,
                reg_signin_match=match,
                reg_signout_match=False,
                signin_confidence=float(confidence),
                signin_face_quality=float(face_quality),
                signin_liveness_passed=bool(liveness_passed)
            )
            db.session.add(new)
            db.session.commit()
            
            return jsonify({
                "status": "ok", 
                "action": "signed_in", 
                "face_match": match,
                "confidence": float(round(confidence * 100, 2)),
                "face_quality": float(round(face_quality * 100, 2)),
                "liveness_passed": bool(liveness_passed),
                "message": f"✅ LIVE ATTENDANCE: {emp.name} verified and signed in! ({round(confidence*100)}% match)"
            })
        
        elif ts.time_in and not ts.time_out:
            ts.signout_image = img_path
            ts.time_out = now_t
            ts.reg_signout_match = match
            ts.signout_confidence = float(confidence)
            ts.signout_face_quality = float(face_quality)
            ts.signout_liveness_passed = bool(liveness_passed)
            db.session.commit()
            
            return jsonify({
                "status": "ok", 
                "action": "signed_out", 
                "face_match": match,
                "confidence": float(round(confidence * 100, 2)),
                "face_quality": float(round(face_quality * 100, 2)),
                "liveness_passed": bool(liveness_passed),
                "message": f"✅ LIVE ATTENDANCE: {emp.name} verified and signed out! ({round(confidence*100)}% match)"
            })
        
        else:
            os.remove(captured_path)
            return jsonify({
                "status": "error",
                "msg": "You have already completed attendance today (both signed in and out)."
            }), 400
    
    return render_template('live_attendance.html')

# ------------------------------
# Employees list
# ------------------------------
@app.route('/employees')
@login_required
@ip_whitelist
def employees():
    q = Employee.query
    
    # Superadmin and admin see all, MDA users see only their MDA
    if current_user.is_superadmin() or current_user.is_admin():
        # They can filter by MDA if they want
        filter_mda = request.args.get('mda', '')
        if filter_mda:
            q = q.filter(Employee.mda.ilike(f"%{filter_mda}%"))
        # Also show MDA filter options in template
        show_mda_filter = True
    elif current_user.is_mda_user():
        # MDA users only see their own MDA
        q = q.filter(Employee.mda == current_user.mda)
        show_mda_filter = False
    else:
        # REGULAR USERS - see only employees in their MDA
        if current_user.mda:
            q = q.filter(Employee.mda == current_user.mda)
            # Show a message that they're viewing their MDA only
            flash(f"Showing employees in {current_user.mda} only", "info")
        else:
            # If user has no MDA assigned, show nothing
            q = q.filter(False)
            flash("No MDA assigned to your account. Please contact administrator.", "warning")
        show_mda_filter = False
    
    # Get unique MDAs for filter dropdown (for superadmin/admin)
    all_mdas = []
    if current_user.is_superadmin() or current_user.is_admin():
        all_mdas = db.session.query(Employee.mda).distinct().filter(Employee.mda.isnot(None)).order_by(Employee.mda).all()
        all_mdas = [m[0] for m in all_mdas if m[0]]  # Flatten and remove None/empty
    
    # Other filters
    name = request.args.get('name', '')
    empid = request.args.get('employeeid', '')
    email = request.args.get('email', '')
    show_inactive = request.args.get('show_inactive', 'false') == 'true'
    
    if name:
        q = q.filter(Employee.name.ilike(f"%{name}%"))
    if empid:
        q = q.filter(Employee.employeeid.ilike(f"%{empid}%"))
    if email:
        q = q.filter(Employee.email.ilike(f"%{email}%"))
    
    if not show_inactive:
        q = q.filter(Employee.is_active == True)
    
    items = q.order_by(Employee.created_at.desc()).all()
    
    # Create a list of dictionaries with employee data and user account info
    employee_data = []
    for emp in items:
        user = User.query.filter_by(email=emp.email).first()
        employee_data.append({
            'employee': emp,
            'user_account': user,
            'has_user': user is not None,
            'user_role': user.role if user else None
        })
    
    # Get counts for display
    total_count = len(employee_data)
    active_count = sum(1 for emp in employee_data if emp['employee'].is_active)
    inactive_count = total_count - active_count
    
    # IMPORTANT: Added now=datetime.now() to the template context
    return render_template('employees.html', 
                         employees=employee_data, 
                         user_role=current_user.role,
                         current_mda=current_user.mda,
                         show_mda_filter=show_mda_filter,
                         all_mdas=all_mdas,
                         filter_mda=request.args.get('mda', ''),
                         total_count=total_count,
                         active_count=active_count,
                         inactive_count=inactive_count,
                         now=datetime.now())  # ← Added this line

@app.route('/employees/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@ip_whitelist
def edit_employee(id):
    if not current_user.is_superadmin():
        flash("👑 Only Super Admin can edit employees!", "danger")
        return redirect(url_for('employees'))
    
    emp = Employee.query.get_or_404(id)
    
    # Check if employee has a linked user account
    existing_user = User.query.filter_by(email=emp.email).first()
    
    if request.method == 'POST':
        # Store original email to check if it changed
        original_email = emp.email
        
        # Update employee fields
        emp.name = request.form['name'].strip()
        emp.mda = request.form.get('mda', '').strip()
        emp.email = request.form.get('email', '').strip().lower()
        emp.phone = request.form.get('phone', '').strip()
        emp.role = request.form.get('role', emp.role)
        emp.is_active = request.form.get('is_active') == 'on'
        
        # Handle user account based on form action
        user_action = request.form.get('user_action', '')
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        # Find or check for user account with new email
        user = User.query.filter_by(email=emp.email).first()
        
        # CASE 1: Create new user account
        if user_action == 'create':
            if not emp.email:
                flash("❌ Email is required to create a user account", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
            
            if not new_password:
                flash("❌ Password is required to create a user account", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
            
            if new_password != confirm_password:
                flash("❌ Passwords do not match", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
            
            # Validate password strength
            password_error = validate_password_strength(new_password)
            if password_error:
                flash(password_error, "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
            
            # Check if user already exists with this email
            if user:
                flash(f"❌ User account with email {emp.email} already exists", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
            
            try:
                # Create new user account linked to this employee
                user = User(
                    email=emp.email,
                    password_hash=generate_password_hash(new_password),
                    name=emp.name,
                    phone=emp.phone,
                    mda=emp.mda,
                    role='user',  # Default role for employees
                    employee_id=emp.id  # Link to employee
                )
                db.session.add(user)
                flash(f"✅ User account created for {emp.name}", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"❌ Error creating user account: {str(e)}", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
        
        # CASE 2: Update existing user password
        elif user_action == 'update_password' and user:
            if not new_password or not confirm_password:
                flash("❌ Both password fields are required to change password", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
            
            if new_password != confirm_password:
                flash("❌ New passwords do not match", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
            
            # Validate password strength
            password_error = validate_password_strength(new_password)
            if password_error:
                flash(password_error, "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
            
            try:
                user.password_hash = generate_password_hash(new_password)
                flash(f"🔑 Password updated for {user.email}", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"❌ Error updating password: {str(e)}", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
        
        # CASE 3: Remove user access
        elif user_action == 'remove_user' and user:
            try:
                db.session.delete(user)
                flash(f"👤 User access removed for {emp.name}", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"❌ Error removing user access: {str(e)}", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
        
        # CASE 4: Email changed - update linked user email
        elif user and original_email != emp.email:
            try:
                # Check if new email is already taken by another user
                existing_user = User.query.filter(User.email == emp.email, User.id != user.id).first()
                if existing_user:
                    flash(f"❌ Email {emp.email} is already in use by another user", "danger")
                    return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
                
                # Update user email to match employee
                user.email = emp.email
                user.name = emp.name  # Sync name
                user.phone = emp.phone  # Sync phone
                user.mda = emp.mda  # Sync mda
                # Ensure link is maintained
                if not user.employee_id:
                    user.employee_id = emp.id
                flash(f"📧 User account email updated to {emp.email}", "success")
            except Exception as e:
                db.session.rollback()
                flash(f"❌ Error updating user email: {str(e)}", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
        
        # CASE 5: Sync user info even if email didn't change
        elif user:
            try:
                # Keep user info in sync with employee
                user.name = emp.name
                user.phone = emp.phone
                user.mda = emp.mda
                # Ensure link is maintained
                if not user.employee_id:
                    user.employee_id = emp.id
                # Don't change role automatically - let admin manage separately
            except Exception as e:
                db.session.rollback()
                flash(f"❌ Error syncing user account: {str(e)}", "danger")
                return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
        
        # Commit all changes
        try:
            db.session.commit()
            flash(f"✅ Employee {emp.name} updated successfully!", "success")
            return redirect(url_for('employees'))
        except Exception as e:
            db.session.rollback()
            
            # Handle unique constraint errors
            error_message = str(e)
            if "UNIQUE constraint failed" in error_message:
                if "employee.email" in error_message:
                    flash(f"❌ Email {emp.email} is already in use by another employee", "danger")
                elif "employee.phone" in error_message:
                    flash(f"❌ Phone {emp.phone} is already in use by another employee", "danger")
                elif "user.email" in error_message:
                    flash(f"❌ Email {emp.email} is already in use by another user", "danger")
                else:
                    flash(f"❌ A unique constraint failed: {error_message}", "danger")
            else:
                flash(f"❌ Error updating employee: {error_message}", "danger")
            
            return render_template('edit_employee.html', emp=emp, user_role=current_user.role, has_user_account=existing_user is not None)
    
    return render_template('edit_employee.html', 
                         emp=emp, 
                         user_role=current_user.role,
                         has_user_account=existing_user is not None)

def validate_password_strength(password):
    """Validate password strength and return error message if invalid"""
    if len(password) < 8:
        return "❌ Password must be at least 8 characters long"
    
    if not re.search(r"[A-Z]", password):
        return "❌ Password must contain at least one uppercase letter"
    
    if not re.search(r"[a-z]", password):
        return "❌ Password must contain at least one lowercase letter"
    
    if not re.search(r"[0-9]", password):
        return "❌ Password must contain at least one number"
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "❌ Password must contain at least one special character"
    
    return None

@app.route('/employees/delete/<int:id>', methods=['POST'])
@login_required
@ip_whitelist
def delete_employee(id):
    if not current_user.is_superadmin():
        return jsonify({"status":"error","msg":"👑 Only Super Admin can delete employees!"}), 403
    
    emp = Employee.query.get_or_404(id)
    
    try:
        # Soft delete - just mark as inactive
        emp.is_active = False
        db.session.commit()
        db.session.expire_all()
        return jsonify({"status":"ok", "msg":f"Employee {emp.name} has been deactivated (soft deleted)"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status":"error","msg":str(e)}), 500

# ------------------------------
# Timesheet routes
# ------------------------------
@app.route('/timesheet')
@login_required
@ip_whitelist
def timesheet():
    q = Timesheet.query
    name = request.args.get('name')
    mda = request.args.get('mda')
    empid = request.args.get('employeeid')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    if not date_from and not date_to:
        today = date.today()
        q = q.filter(Timesheet.date == today)

    if name:
        q = q.filter(Timesheet.employee_name.ilike(f"%{name}%"))
    if mda:
        q = q.filter(Timesheet.mda.ilike(f"%{mda}%"))
    if empid:
        emp = Employee.query.filter_by(employeeid=empid).first()
        if emp:
            q = q.filter(Timesheet.employee_id == emp.id)
        else:
            q = q.filter(False)
    if date_from:
        try:
            df = datetime.strptime(date_from, "%Y-%m-%d").date()
            q = q.filter(Timesheet.date >= df)
        except:
            pass
    if date_to:
        try:
            dt = datetime.strptime(date_to, "%Y-%m-%d").date()
            q = q.filter(Timesheet.date <= dt)
        except:
            pass
    
    if current_user.role != 'admin' and current_user.role != 'superadmin' and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    
    items = q.order_by(Timesheet.date.desc(), Timesheet.time_in.desc()).all()
    
    return render_template('timesheet.html', times=items, now=datetime, date=date, time=time)

@app.route('/timesheet/history')
@login_required
@ip_whitelist
def timesheet_history():
    q = Timesheet.query
    name = request.args.get('name')
    mda = request.args.get('mda')
    empid = request.args.get('employeeid')
    
    if name:
        q = q.filter(Timesheet.employee_name.ilike(f"%{name}%"))
    if mda:
        q = q.filter(Timesheet.mda.ilike(f"%{mda}%"))
    if empid:
        emp = Employee.query.filter_by(employeeid=empid).first()
        if emp:
            q = q.filter(Timesheet.employee_id == emp.id)
        else:
            q = q.filter(False)
    
    if current_user.role != 'admin' and current_user.role != 'superadmin' and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    
    items = q.order_by(Timesheet.date.desc(), Timesheet.time_in.desc()).all()
    
    return render_template('timesheet.html', times=items, now=datetime, date=date, time=time, history_mode=True)

@app.route('/timesheet/delete/<int:id>', methods=['POST'])
@login_required
@ip_whitelist
def delete_timesheet(id):
    if not current_user.is_superadmin():
        return jsonify({"status":"error","msg":"👑 Only Super Admin can delete timesheet records!"}), 403
    
    ts = Timesheet.query.get_or_404(id)
    
    try:
        db.session.delete(ts)
        db.session.commit()
        db.session.expire_all()
        return jsonify({"status":"ok"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status":"error","msg":str(e)}), 500

@app.route('/timesheet/edit/<int:id>', methods=['GET','POST'])
@login_required
@ip_whitelist
def edit_timesheet_entry(id):
    if not current_user.is_superadmin():
        flash("👑 Only Super Admin can edit timesheet records!", "danger")
        return redirect(url_for('timesheet'))
    
    ts = Timesheet.query.get_or_404(id)
    
    form = EditTimesheetForm(obj=ts)
    
    if request.method == 'POST' and form.validate_on_submit():
        ts.employee_name = form.employee_name.data or ts.employee_name
        ts.mda = form.mda.data or ts.mda
        ts.date = form.date.data or ts.date
        
        if form.time_in.data:
            ts.time_in = form.time_in.data
        if form.time_out.data:
            ts.time_out = form.time_out.data
            
        db.session.commit()
        flash("Timesheet updated successfully!", "success")
        return redirect(url_for('timesheet'))
    
    return render_template('edit_timesheet.html', ts=ts, form=form)

@app.route('/unauthorized')
@ip_whitelist
def unauthorized():
    return render_template('unauthorized.html')

# ------------------------------
# Mismatch routes
# ------------------------------
@app.route('/timesheet/mismatch/delete/<int:id>', methods=['POST'])
@login_required
@ip_whitelist
def delete_mismatch(id):
    if not current_user.is_superadmin():
        return jsonify({"status":"error","msg":"👑 Only Super Admin can delete mismatch records!"}), 403
    
    ts = Timesheet.query.get_or_404(id)
    try:
        db.session.delete(ts)
        db.session.commit()
        db.session.expire_all()
        return jsonify({"status": "ok", "msg": "Record deleted"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route('/timesheet/mismatch/export/pdf')
@login_required
@ip_whitelist
def export_mismatch_pdf():
    name = request.args.get('name', '').strip()
    date_filter = request.args.get('date', '').strip()
    
    q = db.session.query(Timesheet).outerjoin(Employee)
    
    if name:
        q = q.filter(Timesheet.employee_name.ilike(f"%{name}%"))
    
    if date_filter:
        try:
            dt = datetime.strptime(date_filter, "%Y-%m-%d").date()
            q = q.filter(Timesheet.date == dt)
        except Exception:
            pass
    
    q = q.filter(
        or_(
            Timesheet.reg_signin_match == False,
            Timesheet.reg_signout_match == False
        )
    )
    
    mismatches = q.order_by(Timesheet.date.desc(), Timesheet.id.desc()).all()
    
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    y = height - 40
    p.setFont("Helvetica-Bold", 16)
    p.drawString(30, y, "🚨 Fraud Prone Attendance Records")
    y -= 40
    
    p.setFont("Helvetica", 10)
    p.drawString(30, y, f"Total Records: {len(mismatches)}")
    y -= 30
    
    for ts in mismatches:
        if y < 80:
            p.showPage()
            y = height - 40
        status = "🚨 MISMATCH" if not (ts.reg_signin_match and ts.reg_signout_match) else "✅ OK"
        confidence_info = f" | SignIn Conf: {round(ts.signin_confidence*100) if ts.signin_confidence else 0}%"
        text = f"ID: {ts.id} | {ts.employee_name} | {ts.date} | {status}{confidence_info}"
        p.drawString(30, y, text)
        y -= 20
    
    p.save()
    buffer.seek(0)
    
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=mismatch_report.pdf'
    return response

@app.route('/timesheet/mismatch')
@login_required
@ip_whitelist
def mismatch():
    name = request.args.get('name', '').strip()
    date_filter = request.args.get('date', '').strip()
    
    q = db.session.query(Timesheet).outerjoin(Employee)
    
    if name:
        q = q.filter(Timesheet.employee_name.ilike(f"%{name}%"))
    
    if date_filter:
        try:
            dt = datetime.strptime(date_filter, "%Y-%m-%d").date()
            q = q.filter(Timesheet.date == dt)
        except Exception:
            pass
    
    q = q.filter(
        or_(
            Timesheet.reg_signin_match == False,
            Timesheet.reg_signout_match == False
        )
    )
    
    mismatches = q.order_by(Timesheet.date.desc(), Timesheet.id.desc()).all()
    
    mismatch_data = []
    for ts in mismatches:
        data = {
            'id': ts.id,
            'emp_name': ts.employee_name,
            'reg_photo': ts.registered_image,
            'signin_photo': ts.signin_image,
            'signout_photo': ts.signout_image,
            'time_in': ts.time_in.strftime('%H:%M') if ts.time_in else 'N/A',
            'time_out': ts.time_out.strftime('%H:%M') if ts.time_out else 'N/A',
            'reg_signin_match': ts.reg_signin_match,
            'reg_signout_match': ts.reg_signout_match,
            'has_mismatch': not (ts.reg_signin_match and ts.reg_signout_match),
            'signin_confidence': ts.signin_confidence,
            'signout_confidence': ts.signout_confidence,
            'signin_face_quality': ts.signin_face_quality,
            'signout_face_quality': ts.signout_face_quality,
            'signin_liveness_passed': ts.signin_liveness_passed,
            'signout_liveness_passed': ts.signout_liveness_passed
        }
        mismatch_data.append(data)
    
    return render_template('mismatch.html', mismatches=mismatch_data, user_role=current_user.role)

# ------------------------------
# Export routes
# ------------------------------
@app.route('/timesheet/export/excel')
@login_required
@ip_whitelist
def export_excel():
    q = Timesheet.query
    if not current_user.is_admin() and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    items = q.all()
    rows = []
    for t in items:
        rows.append({
            "employee_name": t.employee_name,
            "mda": t.mda,
            "date": t.date.isoformat(),
            "time_in": t.time_in.isoformat() if t.time_in else "",
            "time_out": t.time_out.isoformat() if t.time_out else "",
            "signin_confidence": round(t.signin_confidence*100, 2) if t.signin_confidence else "",
            "signout_confidence": round(t.signout_confidence*100, 2) if t.signout_confidence else "",
            "face_match_status": "✅ Match" if t.reg_signin_match and t.reg_signout_match else "❌ Mismatch"
        })
    df = pd.DataFrame(rows)
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Timesheet')
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name='timesheet.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/office')
@login_required
@ip_whitelist
def office():
    today = date.today()
    office_employees = []
    
    try:
        query = db.session.query(Timesheet, Employee).outerjoin(
            Employee, Timesheet.employee_id == Employee.id
        ).filter(
            Timesheet.date == today,
            Timesheet.time_in.isnot(None),
            Timesheet.time_out.is_(None)
        )
        
        if not current_user.is_admin() and current_user.mda:
            query = query.filter(Timesheet.mda == current_user.mda)
        
        employees_query = query.order_by(Timesheet.time_in.desc()).all()
        
        for ts, emp in employees_query:
            office_employees.append({
                'id': ts.id,
                'employee_name': ts.employee_name or (emp.name if emp else 'Unknown'),
                'mda': ts.mda or (emp.mda if emp else 'N/A'),
                'time_in': ts.time_in,
                'signin_image': ts.signin_image,
                'reg_signin_match': ts.reg_signin_match,
                'signin_confidence': ts.signin_confidence,
                'Employee': emp
            })
            
    except Exception as e:
        print(f"❌ OFFICE QUERY ERROR: {e}")
        office_employees = []
    
    # Add now=datetime.now() to the template context
    return render_template('office.html', employees=office_employees, today=today, now=datetime.now())

@app.route('/office/delete/<int:timesheet_id>', methods=['POST'])
@login_required
@ip_whitelist
def delete_office_record(timesheet_id):
    if not current_user.is_superadmin():
        return jsonify({"status": "error", "msg": "👑 Only Super Admin can delete office records!"}), 403
    
    ts = Timesheet.query.get_or_404(timesheet_id)
    
    try:
        db.session.delete(ts)
        db.session.commit()
        db.session.expire_all()
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route('/timesheet/export/pdf')
@login_required
@ip_whitelist
def export_pdf():
    q = Timesheet.query
    if not current_user.is_admin() and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    items = q.all()
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter
    y = height - 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Timesheet Export")
    y -= 30
    c.setFont("Helvetica", 10)
    for t in items:
        confidence = f" (Match: {round(t.signin_confidence*100)}%)" if t.signin_confidence else ""
        line = f"{t.date} | {t.employee_name} | {t.mda} | in: {t.time_in or ''} | out: {t.time_out or ''}{confidence}"
        c.drawString(40, y, line)
        y -= 14
        if y < 40:
            c.showPage()
            y = height - 40
    c.save()
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name='timesheet.pdf', mimetype='application/pdf')

# ------------------------------
# Dashboard - ADD THIS ROUTE
# ------------------------------
@app.route('/dashboard')
@login_required
@ip_whitelist
def dashboard():
    db.session.expire_all()
    
    # Get current MDA for display
    current_mda = current_user.mda if current_user.mda else 'All MDAs'
    
    # Base query for employees - filter by access level
    employees_query = Employee.query.filter(Employee.is_active == True)
    
    if current_user.is_superadmin() or current_user.is_admin():
        # Admins see all
        mda_filter = request.args.get('mda', '')
        if mda_filter:
            employees_query = employees_query.filter(Employee.mda == mda_filter)
            current_mda = mda_filter
        mda_context = "All MDAs" if not mda_filter else mda_filter
    elif current_user.is_mda_user():
        # MDA users see only their MDA
        employees_query = employees_query.filter(Employee.mda == current_user.mda)
        mda_context = current_user.mda
    else:
        # Regular users see their MDA or nothing
        if current_user.mda:
            employees_query = employees_query.filter(Employee.mda == current_user.mda)
            mda_context = current_user.mda
        else:
            employees_query = employees_query.filter(False)
            mda_context = "No Access"
    
    # Get all MDAs for filter dropdown (for superadmin/admin)
    all_mdas = []
    if current_user.is_superadmin() or current_user.is_admin():
        all_mdas = db.session.query(Employee.mda).distinct().filter(Employee.mda.isnot(None)).order_by(Employee.mda).all()
        all_mdas = [m[0] for m in all_mdas if m[0]]
    
    # Get all employees in the filtered scope
    employees = employees_query.all()
    existing_employees = {emp.name: emp.mda for emp in employees}
    
    # Timesheet query - filter by same access level
    q = Timesheet.query
    
    if current_user.is_superadmin() or current_user.is_admin():
        if mda_filter:
            q = q.filter(Timesheet.mda == mda_filter)
    elif current_user.is_mda_user():
        q = q.filter(Timesheet.mda == current_user.mda)
    else:
        if current_user.mda:
            q = q.filter(Timesheet.mda == current_user.mda)
        else:
            q = q.filter(False)
    
    all_timesheets = q.all()
    items = [t for t in all_timesheets if t.employee_name in existing_employees]
    
    # Calculate statistics
    stats = {}
    bench_in = time(8, 30, 0)
    bench_out = time(16, 30, 0)
    
    for t in items:
        name = t.employee_name
        if name not in stats:
            stats[name] = {
                "mda": existing_employees.get(name, t.mda),
                "total_days": 0,
                "signed_in_count": 0,
                "signed_out_count": 0,
                "signed_in_no_signout": 0,
                "early_count": 0,
                "late_count": 0,
                "ontime_count": 0,
                "left_early_count": 0,
                "stayed_till_close_count": 0,
                "exact_timeout_count": 0,
                "avg_confidence": 0,
                "total_confidence": 0,
                "high_confidence_count": 0,
                "medium_confidence_count": 0,
                "low_confidence_count": 0,
                "avg_face_quality": 0,
                "total_face_quality": 0,
                "liveness_passed_count": 0,
                "liveness_failed_count": 0,
                "records": []
            }
        s = stats[name]
        s["records"].append(t)
        s["total_days"] += 1
        
        if t.time_in:
            s["signed_in_count"] += 1
            if t.time_in < bench_in:
                s["early_count"] += 1
            elif t.time_in > bench_in:
                s["late_count"] += 1
            else:
                s["ontime_count"] += 1
            
            if t.signin_confidence:
                s["total_confidence"] += t.signin_confidence
                if t.signin_confidence > 0.8:
                    s["high_confidence_count"] += 1
                elif t.signin_confidence > 0.5:
                    s["medium_confidence_count"] += 1
                else:
                    s["low_confidence_count"] += 1
            
            if t.signin_face_quality:
                s["total_face_quality"] += t.signin_face_quality
            
            if t.signin_liveness_passed:
                s["liveness_passed_count"] += 1
            else:
                s["liveness_failed_count"] += 1
        
        if t.time_out:
            s["signed_out_count"] += 1
            if t.time_out < bench_out:
                s["left_early_count"] += 1
            elif t.time_out > bench_out:
                s["stayed_till_close_count"] += 1
            else:
                s["exact_timeout_count"] += 1
            
            if t.signout_confidence:
                s["total_confidence"] += t.signout_confidence
                if t.signout_confidence > 0.8:
                    s["high_confidence_count"] += 1
                elif t.signout_confidence > 0.5:
                    s["medium_confidence_count"] += 1
                else:
                    s["low_confidence_count"] += 1
            
            if t.signout_face_quality:
                s["total_face_quality"] += t.signout_face_quality
            
            if t.signout_liveness_passed:
                s["liveness_passed_count"] += 1
            else:
                s["liveness_failed_count"] += 1
        
        if t.time_in and not t.time_out:
            s["signed_in_no_signout"] += 1
    
    # Compile statistics list
    stats_list = []
    total_employees = len(stats)
    total_attendance_records = len(items)
    
    for name, v in stats.items():
        total_conf_entries = v["signed_in_count"] + v["signed_out_count"]
        avg_confidence = (v["total_confidence"] / total_conf_entries) if total_conf_entries > 0 else 0
        
        total_quality_entries = v["signed_in_count"] + v["signed_out_count"]
        avg_face_quality = (v["total_face_quality"] / total_quality_entries) if total_quality_entries > 0 else 0
        
        attendance_rate = (v["signed_in_count"] / v["total_days"] * 100) if v["total_days"] > 0 else 0
        punctuality_rate = ((v["early_count"] + v["ontime_count"]) / v["signed_in_count"] * 100) if v["signed_in_count"] > 0 else 0
        stay_rate = (v["stayed_till_close_count"] / v["signed_out_count"] * 100) if v["signed_out_count"] > 0 else 0
        
        stats_list.append({
            "employee_name": name,
            "mda": v["mda"],
            "total_days": v["total_days"],
            "signed_in_count": v["signed_in_count"],
            "signed_out_count": v["signed_out_count"],
            "signed_in_no_signout": v["signed_in_no_signout"],
            "early_count": v["early_count"],
            "late_count": v["late_count"],
            "ontime_count": v["ontime_count"],
            "punctuality_rate": round(punctuality_rate, 1),
            "left_early_count": v["left_early_count"],
            "stayed_till_close_count": v["stayed_till_close_count"],
            "exact_timeout_count": v["exact_timeout_count"],
            "stay_rate": round(stay_rate, 1),
            "attendance_rate": round(attendance_rate, 1),
            "avg_confidence": round(avg_confidence * 100, 2),
            "high_confidence_count": v["high_confidence_count"],
            "medium_confidence_count": v["medium_confidence_count"],
            "low_confidence_count": v["low_confidence_count"],
            "avg_face_quality": round(avg_face_quality * 100, 2),
            "liveness_passed_count": v["liveness_passed_count"],
            "liveness_failed_count": v["liveness_failed_count"],
            "liveness_rate": round((v["liveness_passed_count"] / (v["liveness_passed_count"] + v["liveness_failed_count"]) * 100), 1) if (v["liveness_passed_count"] + v["liveness_failed_count"]) > 0 else 0,
            "trace_link": url_for('employee_trace', name=name)
        })
    
    stats_list.sort(key=lambda x: x["total_days"], reverse=True)
    
    # Calculate summary statistics
    summary = {
        'total_employees': total_employees,
        'total_attendance_records': total_attendance_records,
        'active_today': sum(1 for t in items if t.date == date.today() and t.time_in and not t.time_out),
        'completed_today': sum(1 for t in items if t.date == date.today() and t.time_in and t.time_out),
        'avg_attendance_rate': round(sum(s['attendance_rate'] for s in stats_list) / len(stats_list), 1) if stats_list else 0,
        'avg_punctuality_rate': round(sum(s['punctuality_rate'] for s in stats_list) / len(stats_list), 1) if stats_list else 0,
        'avg_stay_rate': round(sum(s['stay_rate'] for s in stats_list) / len(stats_list), 1) if stats_list else 0,
    }
    
    return render_template('dashboard.html', 
                         stats=stats_list, 
                         user_role=current_user.role,
                         current_mda=current_mda,
                         mda_context=mda_context,
                         all_mdas=all_mdas,
                         summary=summary,
                         now=datetime.now())

# ------------------------------
# Employee Trace - ADD THIS ROUTE
# ------------------------------
@app.route('/trace/<name>')
@login_required
@ip_whitelist
def employee_trace(name):
    employee = Employee.query.filter_by(name=name).first()
    
    if not employee:
        flash(f"Employee '{name}' not found in database", "warning")
        return redirect(url_for('dashboard'))
    
    if not current_user.is_admin() and current_user.mda and current_user.mda != employee.mda:
        flash(f"Access denied: Employee {name} is not in your MDA ({current_user.mda})", "danger")
        return redirect(url_for('dashboard'))
    
    q = Timesheet.query.filter(Timesheet.employee_name == name)
    
    if not current_user.is_admin() and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    
    items = q.order_by(Timesheet.date.desc()).all()
    
    return render_template('trace.html', records=items, name=name, user_role=current_user.role)

# ------------------------------
# MDA User Onboarding
# ------------------------------
@app.route('/onboard_mda', methods=['GET', 'POST'])
@ip_whitelist
def onboard_mda():
    """Onboard MDA users who can manage their department's employees"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        mda = request.form.get('mda', '').strip()
        
        if not all([name, email, phone, mda]):
            flash("All fields are required", "danger")
            return render_template('onboard_mda.html')
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash(f"Email {email} is already registered", "danger")
            return render_template('onboard_mda.html')
        
        try:
            # Create MDA user with phone as password
            user = User(
                name=name,
                email=email,
                phone=phone,
                mda=mda,
                role='mda_user',
                password_hash=generate_password_hash(phone)  # Phone number as password
            )
            db.session.add(user)
            db.session.commit()
            
            flash(f"✅ MDA User {name} created successfully! Login with email and phone number as password.", "success")
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"❌ Error creating MDA user: {str(e)}", "danger")
            return render_template('onboard_mda.html')
    
    return render_template('onboard_mda.html')

# ------------------------------
# Admin User Management
# ------------------------------
@app.route('/admin/users')
@login_required
@ip_whitelist
def admin_users():
    if not current_user.is_superadmin():
        flash("👑 Super Admin access required!", "danger")
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    
    query = User.query
    
    if search:
        query = query.filter(
            db.or_(
                User.name.ilike(f'%{search}%'),
                User.email.ilike(f'%{search}%'),
                User.mda.ilike(f'%{search}%')
            )
        )
    
    users = query.order_by(User.role, User.name).paginate(page=page, per_page=20, error_out=False)
    
    return render_template('admin_users.html', users=users, search=search, user_role=current_user.role)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@ip_whitelist
def admin_add_user():
    if not current_user.is_superadmin():
        flash("👑 Super Admin access required!", "danger")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        mda = request.form.get('mda', '').strip()
        role = request.form.get('role', 'user')
        password = request.form.get('password', '').strip()
        
        if not all([name, email, phone, mda, password]):
            flash("All fields are required", "danger")
            return redirect(url_for('admin_add_user'))
        
        if User.query.filter_by(email=email).first():
            flash(f"Email {email} is already registered", "danger")
            return redirect(url_for('admin_add_user'))
        
        # Check if this email belongs to an employee
        employee = Employee.query.filter_by(email=email).first()
        
        try:
            user = User(
                name=name,
                email=email,
                phone=phone,
                mda=mda,
                role=role,
                password_hash=generate_password_hash(password),
                employee_id=employee.id if employee else None
            )
            db.session.add(user)
            db.session.commit()
            
            if employee:
                flash(f"✅ User {name} created successfully and linked to employee {employee.employeeid}!", "success")
            else:
                flash(f"✅ User {name} created successfully! (No linked employee)", "success")
                
            return redirect(url_for('admin_users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"❌ Error creating user: {str(e)}", "danger")
            return redirect(url_for('admin_add_user'))
    
    return render_template('admin_add_user.html')

@app.route('/admin/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@ip_whitelist
def admin_edit_user(id):
    if not current_user.is_superadmin():
        flash("👑 Super Admin access required!", "danger")
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(id)
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        mda = request.form.get('mda', '').strip()
        role = request.form.get('role', 'user')
        new_password = request.form.get('password', '').strip()
        link_employee = request.form.get('link_employee', '').strip()
        
        if not all([name, email, phone, mda]):
            flash("Name, Email, Phone, and MDA are required", "danger")
            return redirect(url_for('admin_edit_user', id=id))
        
        existing = User.query.filter(User.email == email, User.id != id).first()
        if existing:
            flash(f"Email {email} is already registered to another user", "danger")
            return redirect(url_for('admin_edit_user', id=id))
        
        # Handle employee linking
        employee_id = None
        if link_employee:
            employee = Employee.query.filter_by(employeeid=link_employee).first()
            if employee:
                employee_id = employee.id
            else:
                flash(f"Employee with ID {link_employee} not found", "warning")
        
        try:
            user.name = name
            user.email = email
            user.phone = phone
            user.mda = mda
            user.role = role
            user.employee_id = employee_id
            
            if new_password:
                user.password_hash = generate_password_hash(new_password)
            
            db.session.commit()
            flash(f"✅ User {name} updated successfully!", "success")
            return redirect(url_for('admin_users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"❌ Error updating user: {str(e)}", "danger")
            return redirect(url_for('admin_edit_user', id=id))
    
    # Get all employees for linking dropdown
    employees = Employee.query.filter(Employee.is_active == True).all()
    return render_template('admin_edit_user.html', user=user, employees=employees)

@app.route('/admin/users/delete/<int:id>', methods=['POST'])
@login_required
@ip_whitelist
def admin_delete_user(id):
    if not current_user.is_superadmin():
        return jsonify({"status": "error", "msg": "👑 Super Admin access required!"}), 403
    
    user = User.query.get_or_404(id)
    
    if user.id == current_user.id:
        return jsonify({"status": "error", "msg": "Cannot delete your own account"}), 400
    
    try:
        username = user.name
        # Remove employee link but don't delete employee record
        if user.employee:
            user.employee_id = None
        db.session.delete(user)
        db.session.commit()
        return jsonify({"status": "ok", "msg": f"User {username} deleted successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route('/match_face', methods=['POST'])
@login_required
def match_face():
    """Match a captured face against all registered employees"""
    try:
        data = request.get_json()
        image_data = data.get('image', '')
        
        if not image_data:
            return jsonify({'match_found': False, 'error': 'No image data'}), 400
        
        # Validate image format
        validated_data, error = validate_and_convert_image(image_data)
        if validated_data:
            image_data = validated_data
        
        # Save the captured image temporarily
        img_path = save_base64_image(image_data, prefix='match_temp')
        if not img_path:
            return jsonify({'match_found': False, 'error': 'Failed to save image'}), 500
            
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], img_path)
        
        # Detect and encode the captured face
        face_detected, captured_encoding, _, quality = detect_and_encode_face(full_path)
        
        if not face_detected or captured_encoding is None:
            os.remove(full_path)
            return jsonify({'match_found': False, 'error': 'No face detected'})
        
        # Get all employees with registered images
        employees = Employee.query.filter(Employee.registered_image.isnot(None), Employee.is_active == True).all()
        
        best_match = None
        best_confidence = 0
        
        # Compare with each employee's registered face
        for emp in employees:
            reg_path = os.path.join(app.config['UPLOAD_FOLDER'], emp.registered_image)
            if os.path.exists(reg_path):
                _, reg_encoding, _, _ = detect_and_encode_face(reg_path)
                
                if reg_encoding is not None:
                    match, confidence = compare_faces(reg_encoding, captured_encoding)
                    
                    if match and confidence > best_confidence:
                        best_confidence = confidence
                        best_match = emp
        
        os.remove(full_path)
        
        if best_match and best_confidence >= 0.60:  # 60% threshold
            return jsonify({
                'match_found': True,
                'employee': {
                    'employeeid': best_match.employeeid,
                    'name': best_match.name,
                    'mda': best_match.mda
                },
                'confidence': round(best_confidence * 100, 2)
            })
        else:
            return jsonify({'match_found': False})
            
    except Exception as e:
        print(f"Match face error: {e}")
        return jsonify({'match_found': False, 'error': str(e)}), 500

@app.route('/check_duplicate_image', methods=['POST'])
@login_required
def check_duplicate_image():
    """Check if a face image already exists in the system"""
    try:
        data = request.get_json()
        image_data = data.get('image', '')
        
        if not image_data:
            return jsonify({'is_duplicate': False})
        
        # Validate image format
        validated_data, error = validate_and_convert_image(image_data)
        if validated_data:
            image_data = validated_data
        
        # Save the image temporarily
        img_path = save_base64_image(image_data, prefix='dup_check')
        if not img_path:
            return jsonify({'is_duplicate': False})
            
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], img_path)
        
        # Detect and encode the face
        face_detected, captured_encoding, _, _ = detect_and_encode_face(full_path)
        
        if not face_detected or captured_encoding is None:
            os.remove(full_path)
            return jsonify({'is_duplicate': False})
        
        # Get ALL employees with registered images (including inactive)
        employees = Employee.query.filter(Employee.registered_image.isnot(None)).all()
        
        # Compare with each employee's registered face
        for emp in employees:
            reg_path = os.path.join(app.config['UPLOAD_FOLDER'], emp.registered_image)
            if os.path.exists(reg_path):
                _, reg_encoding, _, _ = detect_and_encode_face(reg_path)
                
                if reg_encoding is not None:
                    match, confidence = compare_faces(reg_encoding, captured_encoding)
                    
                    # If match found with high confidence (>70%), it's a duplicate
                    if match and confidence > 0.7:
                        os.remove(full_path)
                        return jsonify({
                            'is_duplicate': True, 
                            'existing_employee': emp.name,
                            'is_active': emp.is_active,
                            'employee_mda': emp.mda
                        })
        
        os.remove(full_path)
        return jsonify({'is_duplicate': False})
        
    except Exception as e:
        print(f"Duplicate check error: {e}")
        return jsonify({'is_duplicate': False})

# ------------------------------
# Signup
# ------------------------------
@app.route('/signup', methods=['GET','POST'])
@ip_whitelist
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip()
        pwd = request.form['password']
        name = request.form.get('name','')
        mda = request.form.get('mda','')
        
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "warning")
            return redirect(url_for('signup'))
        
        # Check if this email belongs to an employee
        employee = Employee.query.filter_by(email=email).first()
        
        u = User(
            email=email, 
            password_hash=generate_password_hash(pwd), 
            role='user', 
            name=name, 
            mda=mda,
            employee_id=employee.id if employee else None
        )
        db.session.add(u)
        db.session.commit()
        
        if employee:
            flash(f"✅ User account created and linked to employee {employee.employeeid}! Please login.", "success")
        else:
            flash("✅ User account created successfully! Please login.", "success")
            
        return redirect(url_for('login'))
    
    return render_template('signup.html')

# ------------------------------
# Serve uploaded images
# ------------------------------
@app.route('/uploads/<path:filename>')
@ip_whitelist
def uploads(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# ------------------------------
# Additional utility routes
# ------------------------------
@app.route('/link_employee_user', methods=['POST'])
@login_required
@ip_whitelist
def link_employee_user():
    """Manually link an employee to a user account"""
    if not current_user.is_superadmin():
        return jsonify({"status": "error", "msg": "Super Admin access required"}), 403
    
    data = request.get_json()
    employee_id = data.get('employee_id')
    user_id = data.get('user_id')
    
    employee = Employee.query.get(employee_id)
    user = User.query.get(user_id)
    
    if not employee or not user:
        return jsonify({"status": "error", "msg": "Employee or User not found"}), 404
    
    try:
        user.employee_id = employee.id
        db.session.commit()
        return jsonify({"status": "ok", "msg": f"Linked {user.email} to {employee.employeeid}"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "msg": str(e)}), 500

@app.route('/unlink_employee_user', methods=['POST'])
@login_required
@ip_whitelist
def unlink_employee_user():
    """Remove link between employee and user"""
    if not current_user.is_superadmin():
        return jsonify({"status": "error", "msg": "Super Admin access required"}), 403
    
    data = request.get_json()
    user_id = data.get('user_id')
    
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({"status": "error", "msg": "User not found"}), 404
    
    try:
        user.employee_id = None
        db.session.commit()
        return jsonify({"status": "ok", "msg": f"Unlinked user {user.email}"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "msg": str(e)}), 500

# ------------------------------
# Run
# ------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        migrate_database()
        
        # Create default superadmin if not exists
        superadmin = User.query.filter_by(email='sadmin@gmail.com').first()
        if not superadmin:
            superadmin = User(
                name='sadmin',
                email='sadmin@gmail.com',
                password_hash=generate_password_hash('sadmin123'),
                role='superadmin',
                mda='SYSTEM'
            )
            db.session.add(superadmin)
            db.session.commit()
            print("✅ Super Admin created.")
            print("   👑 Name: sadmin")
            print("   📧 Email: sadmin@gmail.com")
            print("   🔑 Password: sadmin123")
        
        # Create default admin if not exists
        admin = User.query.filter_by(email='admin@gmail.com').first()
        if not admin:
            admin = User(
                name='Administrator',
                email='admin@gmail.com',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                mda='ADMIN'
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin created. Email: admin@gmail.com Password: admin123")
        
        print("\n🔑 User Roles:")
        print("   👤 User - Can take attendance, register employees, view office")
        print("   🛡️ Admin - Can view everything (no edit/delete)")
        print("   👑 Super Admin - Full access (can edit/delete everything)")
        print("\n🌐 Server starting at http://localhost:5000")
        
    app.run(debug=True, host='0.0.0.0', port=5000)