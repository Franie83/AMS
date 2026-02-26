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
import numpy as np
# ------------------------------
# IP Whitelist Configuration
# ------------------------------
# List of allowed IP addresses
ALLOWED_IPS = [
    '127.0.0.1',       # Localhost (for development)
    '::1',             # IPv6 localhost
    '192.168.97.212',    # Your current IP
    # Add more IPs as needed - office IPs, VPN IPs, etc.
]

def ip_whitelist(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
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
        user_ip = get_client_ip()
        print(f"🔍 Access attempt from IP (behind proxy): {user_ip}")
        
        if user_ip not in ALLOWED_IPS:
            print(f"❌ Blocked access from unauthorized IP: {user_ip}")
            return "Access Denied - Unauthorized IP Address", 403
        
        return f(*args, **kwargs)
    return decorated_function
# ------------------------------
# Config
# ------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-me-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'attendance.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ------------------------------
# Context Processor for templates
# ------------------------------
@app.context_processor
def utility_processor():
    return {'now': datetime.now}


# ------------------------------
# Models
# ------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    name = db.Column(db.String(150))
    phone = db.Column(db.String(50), nullable=True)
    mda = db.Column(db.String(150), nullable=True)

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)
    
    def is_superadmin(self):
        return self.role == 'superadmin'
    
    def is_admin(self):
        return self.role == 'admin' or self.role == 'superadmin'

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employeeid = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    mda = db.Column(db.String(150))
    email = db.Column(db.String(150))
    phone = db.Column(db.String(50))
    role = db.Column(db.String(50))
    registered_image = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
# Face Recognition Utilities
# ------------------------------
def save_base64_image(b64_data, prefix='img'):
    if not b64_data:
        return None
    if ',' in b64_data:
        _, b64 = b64_data.split(',', 1)
    else:
        b64 = b64_data
    try:
        img_data = base64.b64decode(b64)
        filename = f"{prefix}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}.jpg"
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(path, 'wb') as f:
            f.write(img_data)
        return filename
    except Exception as e:
        print(f"Error saving image: {e}")
        return None

def image_hash(path):
    img = Image.open(path).convert('L').resize((256,256))
    return imagehash.phash(img)

def detect_and_encode_face(image_path):
    try:
        img = face_recognition.load_image_file(image_path)
        face_locations = face_recognition.face_locations(img)
        
        if len(face_locations) == 0:
            return False, None, None, 0
        
        face_encodings = face_recognition.face_encodings(img, face_locations)
        
        if len(face_encodings) == 0:
            return False, None, None, 0
        
        face_location = face_locations[0]
        top, right, bottom, left = face_location
        face_width = right - left
        face_height = bottom - top
        img_height, img_width = img.shape[:2] if hasattr(img, 'shape') else (480, 640)
        
        face_area_ratio = (face_width * face_height) / (img_width * img_height)
        quality_score = min(face_area_ratio * 10, 1.0)
        
        return True, face_encodings[0], face_location, quality_score
        
    except Exception as e:
        print(f"Face detection error: {e}")
        return False, None, None, 0

def compare_faces(registered_encoding, captured_encoding, threshold=0.6):
    try:
        if registered_encoding is None or captured_encoding is None:
            return False, 0
        
        face_distance = face_recognition.face_distance([registered_encoding], captured_encoding)
        confidence = 1 - face_distance[0]
        
        match = face_recognition.compare_faces([registered_encoding], captured_encoding, tolerance=0.6)[0]
        
        return match and confidence > threshold, confidence
        
    except Exception as e:
        print(f"Face comparison error: {e}")
        return False, 0

def check_liveness(image_path):
    try:
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        eye_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_eye.xml')
        
        img = cv2.imread(image_path)
        if img is None:
            return False
        
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        faces = face_cascade.detectMultiScale(gray, 1.3, 5)
        
        if len(faces) == 0:
            return False
        
        for (x, y, w, h) in faces:
            roi_gray = gray[y:y+h, x:x+w]
            eyes = eye_cascade.detectMultiScale(roi_gray)
            
            if len(eyes) >= 2:
                return True
        
        return False
        
    except Exception as e:
        print(f"Liveness check error: {e}")
        return False

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

def migrate_database():
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('timesheet')]
            
            new_columns = [
                ('signin_confidence', 'FLOAT DEFAULT 0.0'),
                ('signout_confidence', 'FLOAT DEFAULT 0.0'),
                ('signin_face_quality', 'FLOAT DEFAULT 0.0'),
                ('signout_face_quality', 'FLOAT DEFAULT 0.0'),
                ('signin_liveness_passed', 'BOOLEAN DEFAULT 0'),
                ('signout_liveness_passed', 'BOOLEAN DEFAULT 0')
            ]
            
            for col_name, col_type in new_columns:
                if col_name not in columns:
                    db.session.execute(f'ALTER TABLE timesheet ADD COLUMN {col_name} {col_type}')
                    print(f"Added column: {col_name}")
            
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
# API Endpoints
# ------------------------------
@app.route('/detect_face', methods=['POST'])
@ip_whitelist
def detect_face_api():
    try:
        data = request.get_json()
        image_data = data.get('image', '')
        
        if not image_data:
            return jsonify({'face_detected': False, 'error': 'No image data'}), 400
        
        img_path = save_base64_image(image_data, prefix='temp_detect')
        if not img_path:
            return jsonify({'face_detected': False, 'error': 'Failed to save image'}), 500
            
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], img_path)
        
        face_detected, encoding, location, quality = detect_and_encode_face(full_path)
        liveness_passed = check_liveness(full_path) if face_detected else False
        
        if os.path.exists(full_path):
            os.remove(full_path)
        
        return jsonify({
            'face_detected': face_detected,
            'quality': round(quality, 2),
            'liveness_passed': liveness_passed,
            'message': 'Face detected' if face_detected else 'No face detected'
        })
        
    except Exception as e:
        return jsonify({'face_detected': False, 'error': str(e)}), 500

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
            role_emoji = "👑" if user.role == 'superadmin' else "🛡️" if user.role == 'admin' else "👤"
            flash(f"{role_emoji} Welcome back {user.name}! ({user.role})", "success")
            return redirect(url_for('dashboard'))
        
        employee = Employee.query.filter_by(email=email).first()
        if employee and employee.phone == password:
            user = User.query.filter_by(email=email).first()
            if not user:
                user = User(
                    email=email,
                    password_hash=generate_password_hash(employee.phone),
                    name=employee.name,
                    mda=employee.mda,
                    role='user'
                )
                db.session.add(user)
                db.session.commit()
            
            login_user(user)
            flash(f"👤 Welcome back {employee.name}!", "success")
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
    if request.method == 'POST':
        raw_name = request.form.get('name', '')
        raw_email = request.form.get('email', '')
        raw_phone = request.form.get('phone', '')
        
        name = raw_name.strip()
        email = raw_email.strip().lower()
        phone = raw_phone.strip()
        role = 'user'
        
        mda = current_user.mda if current_user.mda else ''
        
        existing_employee = Employee.query.filter(Employee.email.ilike(email)).first()
        if existing_employee:
            error_msg = f"❌ Email {raw_email} is already registered to employee {existing_employee.name}"
            flash(error_msg, "danger")
            return render_template('register.html', name=name, email=raw_email, phone=phone, mda=mda)
        
        existing_phone = Employee.query.filter_by(phone=phone).first()
        if existing_phone:
            error_msg = f"❌ Phone {phone} is already registered to employee {existing_phone.name}"
            flash(error_msg, "danger")
            return render_template('register.html', name=name, email=raw_email, phone=phone, mda=mda)
        
        try:
            empid = generate_employeeid(name)
            
            existing_id = Employee.query.filter_by(employeeid=empid).first()
            if existing_id:
                import random
                empid = f"{empid[:4]}{random.randint(1000, 9999)}"
            
            b64 = request.form.get('face_image')
            img_filename = None
            face_quality = 0
            
            if b64:
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
                mda=mda,
                email=email,
                phone=phone,
                role=role,
                registered_image=img_filename
            )
            
            db.session.add(emp)
            db.session.commit()
            
            flash(f"✅ Employee {empid} registered successfully! (MDA: {mda}, Face quality: {round(face_quality*100)}%)", "success")
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
                    flash("❌ A unique constraint failed.", "danger")
            else:
                flash(f"❌ Registration failed: {error_message}", "danger")
            
            db.session.rollback()
            
            if 'img_filename' in locals() and img_filename:
                full_path = os.path.join(app.config['UPLOAD_FOLDER'], img_filename)
                if os.path.exists(full_path):
                    os.remove(full_path)
            
            return render_template('register.html', name=name, email=raw_email, phone=phone, mda=mda)
    
    return render_template('register.html')

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
        emp = Employee.query.filter_by(employeeid=empid).first()
        if not emp:
            return jsonify({"status":"error","msg":"unknown employeeid"}), 404
        if not b64:
            return jsonify({"status":"error","msg":"no image"}), 400
        
        img_path = save_base64_image(b64, prefix=f"attendance_{empid}")
        if not img_path:
            return jsonify({"status":"error","msg":"Failed to save image"}), 500
            
        captured_path = os.path.join(app.config['UPLOAD_FOLDER'], img_path)
        
        face_detected, captured_encoding, _, face_quality = detect_and_encode_face(captured_path)
        
        if not face_detected:
            os.remove(captured_path)
            return jsonify({"status":"error","msg":"No face detected. Please ensure your face is clearly visible."}), 400
        
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
@app.route('/live_attendance', methods=['GET','POST'])
@login_required
@ip_whitelist
def live_attendance():
    if request.method == 'POST':
        empid = request.form.get('employeeid', '').strip()
        b64 = request.form.get('captured_image')
        
        if not empid:
            return jsonify({"status":"error","msg":"employeeid required"}), 400
        emp = Employee.query.filter_by(employeeid=empid).first()
        if not emp:
            return jsonify({"status":"error","msg":"unknown employeeid"}), 404
        if not b64:
            return jsonify({"status":"error","msg":"no image"}), 400
        
        img_path = save_base64_image(b64, prefix=f"live_{empid}")
        if not img_path:
            return jsonify({"status":"error","msg":"Failed to save image"}), 500
            
        captured_path = os.path.join(app.config['UPLOAD_FOLDER'], img_path)
        
        face_detected, captured_encoding, _, face_quality = detect_and_encode_face(captured_path)
        
        if not face_detected:
            os.remove(captured_path)
            return jsonify({"status":"error","msg":"No face detected. Please ensure your face is clearly visible."}), 400
        
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
                "status":"error",
                "msg":f"Face does not match registered employee. Confidence: {round(confidence*100)}% (need 60%)"
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
                "status":"ok", 
                "action":"signed_in", 
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
                "status":"ok", 
                "action":"signed_out", 
                "face_match": match,
                "confidence": float(round(confidence * 100, 2)),
                "face_quality": float(round(face_quality * 100, 2)),
                "liveness_passed": bool(liveness_passed),
                "message": f"✅ LIVE ATTENDANCE: {emp.name} verified and signed out! ({round(confidence*100)}% match)"
            })
        
        else:
            os.remove(captured_path)
            return jsonify({
                "status":"error",
                "msg":"You have already completed attendance today (both signed in and out)."
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
    
    name = request.args.get('name', '')
    mda = request.args.get('mda', '')
    empid = request.args.get('employeeid', '')
    email = request.args.get('email', '')
    
    if name:
        q = q.filter(Employee.name.ilike(f"%{name}%"))
    if mda:
        q = q.filter(Employee.mda.ilike(f"%{mda}%"))
    if empid:
        q = q.filter(Employee.employeeid.ilike(f"%{empid}%"))
    if email:
        q = q.filter(Employee.email.ilike(f"%{email}%"))
    
    if current_user.is_superadmin():
        pass
    elif current_user.is_admin():
        pass
    else:
        if current_user.mda:
            q = q.filter(Employee.mda == current_user.mda)
        else:
            q = q.filter(False)
    
    items = q.order_by(Employee.created_at.desc()).all()
    
    return render_template('employees.html', employees=items, user_role=current_user.role)

@app.route('/employees/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@ip_whitelist
def edit_employee(id):
    if not current_user.is_superadmin():
        flash("👑 Only Super Admin can edit employees!", "danger")
        return redirect(url_for('employees'))
    
    try:
        emp = Employee.query.get_or_404(id)
    except Exception as e:
        app.logger.error(f"Error fetching employee {id}: {e}")
        flash("Employee not found.", "danger")
        return redirect(url_for('employees'))

    if request.method == 'POST':
        emp.name = request.form['name']
        emp.mda = request.form['mda']
        emp.email = request.form['email']
        emp.phone = request.form['phone']
        emp.role = request.form.get('role', emp.role)
        
        try:
            db.session.commit()
            flash(f"✅ Employee {emp.name} updated successfully!", "success")
            return redirect(url_for('employees'))
        except Exception as e:
            db.session.rollback()
            flash(f"❌ Error updating employee: {str(e)}", "danger")
            return render_template('edit_employee.html', emp=emp)

    return render_template('edit_employee.html', emp=emp, user_role=current_user.role)

@app.route('/employees/delete/<int:id>', methods=['POST'])
@login_required
@ip_whitelist
def delete_employee(id):
    if not current_user.is_superadmin():
        return jsonify({"status":"error","msg":"👑 Only Super Admin can delete employees!"}), 403
    
    emp = Employee.query.get_or_404(id)
    
    try:
        db.session.delete(emp)
        db.session.commit()
        db.session.expire_all()
        return jsonify({"status":"ok", "msg":f"Employee {emp.name} deleted successfully"})
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
    
    return render_template('office.html', employees=office_employees, today=today)

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
# Dashboard
# ------------------------------
@app.route('/dashboard')
@login_required
@ip_whitelist
def dashboard():
    db.session.expire_all()
    
    employees_query = Employee.query
    
    if not current_user.is_admin() and current_user.mda:
        employees_query = employees_query.filter(Employee.mda == current_user.mda)
    
    existing_employees = {}
    for emp in employees_query.all():
        existing_employees[emp.name] = emp.mda
    
    q = Timesheet.query
    
    if not current_user.is_admin() and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    
    all_timesheets = q.all()
    
    items = [t for t in all_timesheets if t.employee_name in existing_employees]
    
    stats = {}
    bench_in = time(8,30,0)
    bench_out = time(16,30,0)
    
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

    stats_list = []
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
    
    return render_template('dashboard.html', stats=stats_list, user_role=current_user.role)

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
        
        try:
            user = User(
                name=name,
                email=email,
                mda=mda,
                role=role,
                password_hash=generate_password_hash(password)
            )
            db.session.add(user)
            db.session.commit()
            
            flash(f"✅ User {name} created successfully!", "success")
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
        
        if not all([name, email, phone, mda]):
            flash("Name, Email, Phone, and MDA are required", "danger")
            return redirect(url_for('admin_edit_user', id=id))
        
        existing = User.query.filter(User.email == email, User.id != id).first()
        if existing:
            flash(f"Email {email} is already registered to another user", "danger")
            return redirect(url_for('admin_edit_user', id=id))
        
        try:
            user.name = name
            user.email = email
            user.phone = phone
            user.mda = mda
            user.role = role
            
            if new_password:
                user.password_hash = generate_password_hash(new_password)
            
            db.session.commit()
            flash(f"✅ User {name} updated successfully!", "success")
            return redirect(url_for('admin_users'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"❌ Error updating user: {str(e)}", "danger")
            return redirect(url_for('admin_edit_user', id=id))
    
    return render_template('admin_edit_user.html', user=user)

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
        employees = Employee.query.filter(Employee.registered_image.isnot(None)).all()
        
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
        
        # Get all employees with registered images
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
                        return jsonify({'is_duplicate': True})
        
        os.remove(full_path)
        return jsonify({'is_duplicate': False})
        
    except Exception as e:
        print(f"Duplicate check error: {e}")
        return jsonify({'is_duplicate': False})
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
        
        u = User(
            email=email, 
            password_hash=generate_password_hash(pwd), 
            role='user', 
            name=name, 
            mda=mda
        )
        db.session.add(u)
        db.session.commit()
        
        flash("User created successfully! Please login.", "success")
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
# Run
# ------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        migrate_database()
        
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