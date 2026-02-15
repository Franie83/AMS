import os
import io
import base64
from datetime import datetime, date, time
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_file, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import imagehash
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

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
# Models
# ------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'admin' or 'user'
    name = db.Column(db.String(150))
    mda = db.Column(db.String(150), nullable=True)  # for user role scoping

    def check_password(self, pwd):
        return check_password_hash(self.password_hash, pwd)

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employeeid = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    mda = db.Column(db.String(150))
    email = db.Column(db.String(150))
    phone = db.Column(db.String(50))
    role = db.Column(db.String(50))
    registered_image = db.Column(db.String(300))  # filepath
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------------------
# Utilities
# ------------------------------
def save_base64_image(b64_data, prefix='img'):
    # b64_data expected like "data:image/png;base64,...."
    if ',' in b64_data:
        header, b64 = b64_data.split(',', 1)
    else:
        b64 = b64_data
    img_data = base64.b64decode(b64)
    filename = f"{prefix}_{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}.png"
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(path, 'wb') as f:
        f.write(img_data)
    return path

def image_hash(path):
    img = Image.open(path).convert('L').resize((256,256))
    return imagehash.phash(img)

def images_mismatch(p1, p2):
    # returns True if different by perceptual hash threshold
    try:
        h1 = image_hash(p1); h2 = image_hash(p2)
        diff = h1 - h2
        return diff > 8  # threshold, tweak as needed
    except Exception:
        return True

def generate_employeeid():
    # e.g., EMP202511150001
    today_str = datetime.utcnow().strftime('%Y%m%d')
    counter = Employee.query.filter(Employee.employeeid.like(f"EMP{today_str}%")).count() + 1
    return f"EMP{today_str}{counter:04d}"

# ------------------------------
# Auth helpers
# ------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Admin access required", "warning")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# ------------------------------
# Routes
# ------------------------------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/setup')
def setup():
    # create DB and admin user if not exists
    db.create_all()
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
        return "Admin user created: admin@gmail.com / admin123 - restart app and login"
    return "Setup has already been done."

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for('login'))

# ------------------------------
# Register Employee
# ------------------------------
@app.route('/register', methods=['GET','POST'])
@login_required
def register():
    # Only admin and user both can register employee, but user will be limited to their mda.
    if request.method == 'POST':
        name = request.form['name'].strip()
        mda = request.form.get('mda','').strip()
        email = request.form.get('email','').strip()
        phone = request.form.get('phone','').strip()
        role = request.form.get('role','user').strip()

        # generate employee id
        empid = generate_employeeid()
        # Expect client to send captured image as base64 at "captured_image"
        b64 = request.form.get('captured_image')
        img_path = None
        if b64:
            img_path = save_base64_image(b64, prefix=f"registered_{empid}")

        emp = Employee(
            employeeid=empid,
            name=name,
            mda=mda,
            email=email,
            phone=phone,
            role=role,
            registered_image=img_path
        )
        db.session.add(emp)
        db.session.commit()
        return jsonify({"status":"ok", "employeeid": empid})
    # GET
    return render_template('register.html')

# ------------------------------
# Take Attendance
# ------------------------------
@app.route('/take_attendance', methods=['GET','POST'])
@login_required
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
        img_path = save_base64_image(b64, prefix=f"signin_{empid}")

        # find timesheet for this employee today
        today = date.today()
        ts = Timesheet.query.filter_by(employee_id=emp.id, date=today).order_by(Timesheet.id.desc()).first()
        now_t = datetime.now().time()
        if ts is None or ts.time_in is None:
            # create new sign-in record
            new = Timesheet(
                employee_id=emp.id,
                employee_name=emp.name,
                mda=emp.mda,
                registered_image=emp.registered_image,
                signin_image=img_path,
                date=today,
                time_in=now_t
            )
            db.session.add(new)
            db.session.commit()
            return jsonify({"status":"ok","action":"signed_in"})
        else:
            # update sign out
            ts.signout_image = img_path
            ts.time_out = now_t
            db.session.commit()
            return jsonify({"status":"ok","action":"signed_out"})
    return render_template('take_attendance.html')

# ------------------------------
# Employees list, edit, delete
# ------------------------------
@app.route('/employees')
@login_required
def employees():
    q = Employee.query
    # filtering
    name = request.args.get('name')
    mda = request.args.get('mda')
    empid = request.args.get('employeeid')
    if name:
        q = q.filter(Employee.name.ilike(f"%{name}%"))
    if mda:
        q = q.filter(Employee.mda.ilike(f"%{mda}%"))
    if empid:
        q = q.filter(Employee.employeeid.ilike(f"%{empid}%"))
    # role-based scoping: user only see same mda
    if current_user.role != 'admin' and current_user.mda:
        q = q.filter(Employee.mda == current_user.mda)
    items = q.order_by(Employee.created_at.desc()).all()
    return render_template('employees.html', employees=items)

@app.route('/employees/edit/<int:id>', methods=['GET','POST'])
@login_required
def edit_employee(id):
    emp = Employee.query.get_or_404(id)
    # allow only admin or same mda admin? admin can edit all.
    if current_user.role != 'admin' and current_user.mda and current_user.mda != emp.mda:
        flash("Not authorized", "warning")
        return redirect(url_for('employees'))
    if request.method == 'POST':
        emp.name = request.form['name']
        emp.mda = request.form['mda']
        emp.email = request.form['email']
        emp.phone = request.form['phone']
        emp.role = request.form.get('role', emp.role)
        db.session.commit()
        flash("Employee updated", "success")
        return redirect(url_for('employees'))
    return render_template('edit_employee.html', emp=emp)

@app.route('/employees/delete/<int:id>', methods=['POST'])
@login_required
def delete_employee(id):
    emp = Employee.query.get_or_404(id)
    if current_user.role != 'admin' and current_user.mda and current_user.mda != emp.mda:
        return jsonify({"status":"error","msg":"not authorized"}), 403
    db.session.delete(emp)
    db.session.commit()
    return jsonify({"status":"ok"})

# ------------------------------
# Timesheet list, edit, delete
# ------------------------------
@app.route('/timesheet')
@login_required
def timesheet():
    q = Timesheet.query
    name = request.args.get('name')
    mda = request.args.get('mda')
    empid = request.args.get('employeeid')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    if name:
        q = q.filter(Timesheet.employee_name.ilike(f"%{name}%"))
    if mda:
        q = q.filter(Timesheet.mda.ilike(f"%{mda}%"))
    if empid:
        # lookup employee id via related employee
        emp = Employee.query.filter_by(employeeid=empid).first()
        if emp:
            q = q.filter(Timesheet.employee_id == emp.id)
        else:
            q = q.filter(False)  # no results
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
    # role based scoping
    if current_user.role != 'admin' and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    items = q.order_by(Timesheet.date.desc(), Timesheet.time_in.desc()).all()
    return render_template('timesheet.html', times=items)

@app.route('/timesheet/delete/<int:id>', methods=['POST'])
@login_required
def delete_timesheet(id):
    ts = Timesheet.query.get_or_404(id)
    if current_user.role != 'admin' and current_user.mda and current_user.mda != ts.mda:
        return jsonify({"status":"error","msg":"not authorized"}), 403
    db.session.delete(ts)
    db.session.commit()
    return jsonify({"status":"ok"})

@app.route('/timesheet/edit/<int:id>', methods=['GET','POST'])
@login_required
def edit_timesheet(id):
    ts = Timesheet.query.get_or_404(id)
    if request.method == 'POST':
        # allow update of times/images
        ts.employee_name = request.form.get('employee_name', ts.employee_name)
        ts.mda = request.form.get('mda', ts.mda)
        # times
        tin = request.form.get('time_in')
        tout = request.form.get('time_out')
        if tin:
            try:
                ts.time_in = datetime.strptime(tin, "%H:%M:%S").time()
            except:
                pass
        if tout:
            try:
                ts.time_out = datetime.strptime(tout, "%H:%M:%S").time()
            except:
                pass
        db.session.commit()
        flash("Timesheet updated", "success")
        return redirect(url_for('timesheet'))
    return render_template('edit_timesheet.html', ts=ts)

# ------------------------------
# Image mismatch detection
# ------------------------------
@app.route('/timesheet/mismatch')
@login_required
def mismatch():
    # select all timesheet entries where registered_image != signin_image or signin_image != signout_image
    q = Timesheet.query
    if current_user.role != 'admin' and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    items = q.all()
    mismatches = []
    for t in items:
        if not t.registered_image or not t.signin_image:
            continue
        reg = t.registered_image
        sin = t.signin_image
        s_out = t.signout_image
        m1 = images_mismatch(reg, sin)
        m2 = False
        if s_out:
            m2 = images_mismatch(sin, s_out)
        if m1 or m2:
            mismatches.append({
                "timesheet_id": t.id,
                "employee_name": t.employee_name,
                "mda": t.mda,
                "date": str(t.date),
                "registered_image": t.registered_image,
                "signin_image": t.signin_image,
                "signout_image": t.signout_image,
                "mismatch_reg_signin": m1,
                "mismatch_signin_signout": m2
            })
    return render_template('mismatch.html', mismatches=mismatches)

# ------------------------------
# Export to excel and pdf
# ------------------------------
@app.route('/timesheet/export/excel')
@login_required
def export_excel():
    q = Timesheet.query
    if current_user.role != 'admin' and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    items = q.all()
    rows = []
    for t in items:
        rows.append({
            "employee_name": t.employee_name,
            "mda": t.mda,
            "date": t.date.isoformat(),
            "time_in": t.time_in.isoformat() if t.time_in else "",
            "time_out": t.time_out.isoformat() if t.time_out else ""
        })
    df = pd.DataFrame(rows)
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Timesheet')
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name='timesheet.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/timesheet/export/pdf')
@login_required
def export_pdf():
    q = Timesheet.query
    if current_user.role != 'admin' and current_user.mda:
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
        line = f"{t.date} | {t.employee_name} | {t.mda} | in: {t.time_in or ''} | out: {t.time_out or ''}"
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
def dashboard():
    # compute per-employee stats
    q = Timesheet.query
    if current_user.role != 'admin' and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    items = q.all()
    stats = {}
    # benchmark times
    bench_in = time(8,30,0)
    bench_out = time(15,30,0)
    for t in items:
        name = t.employee_name
        if name not in stats:
            stats[name] = {
                "mda": t.mda,
                "signed_in_count": 0,
                "signed_out_count": 0,
                "signed_in_no_signout": 0,
                "late_count": 0,
                "early_count": 0,
                "left_before_time": 0,
                "waited_till_closing": 0,
                "records": []
            }
        s = stats[name]
        s["records"].append(t)
        if t.time_in:
            s["signed_in_count"] += 1
            if t.time_in > bench_in:
                s["late_count"] += 1
            else:
                s["early_count"] += 1
        if t.time_out:
            s["signed_out_count"] += 1
            if t.time_out < bench_out:
                s["left_before_time"] += 1
            if t.time_out >= bench_out:
                s["waited_till_closing"] += 1
        if t.time_in and not t.time_out:
            s["signed_in_no_signout"] += 1

    # Convert to list for template
    stats_list = []
    for name, v in stats.items():
        stats_list.append({
            "employee_name": name,
            "mda": v["mda"],
            "signed_in_count": v["signed_in_count"],
            "signed_out_count": v["signed_out_count"],
            "signed_in_no_signout": v["signed_in_no_signout"],
            "late_count": v["late_count"],
            "early_count": v["early_count"],
            "left_before_time": v["left_before_time"],
            "waited_till_closing": v["waited_till_closing"],
            "trace_link": url_for('employee_trace', name=name)
        })
    return render_template('dashboard.html', stats=stats_list)

@app.route('/trace/<name>')
@login_required
def employee_trace(name):
    # show full records for an employee
    q = Timesheet.query.filter(Timesheet.employee_name == name)
    if current_user.role != 'admin' and current_user.mda:
        q = q.filter(Timesheet.mda == current_user.mda)
    items = q.order_by(Timesheet.date.desc()).all()
    return render_template('trace.html', records=items, name=name)

# ------------------------------
# Simple user signup for 'user' role (not admin)
# ------------------------------
@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email'].strip()
        pwd = request.form['password']
        name = request.form.get('name','')
        mda = request.form.get('mda','')
        if User.query.filter_by(email=email).first():
            flash("Email exists", "warning")
            return redirect(url_for('signup'))
        u = User(email=email, password_hash=generate_password_hash(pwd), role='user', name=name, mda=mda)
        db.session.add(u); db.session.commit()
        flash("User created, please login", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

# ------------------------------
# Serve uploaded images
# ------------------------------
@app.route('/uploads/<path:filename>')
def uploads(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

# ------------------------------
# Run
# ------------------------------
if __name__ == '__main__':
    db.create_all()
    # ensure admin exists
    admin = User.query.filter_by(email='admin@gmail.com').first()
    if not admin:
        admin = User(email='admin@gmail.com', password_hash=generate_password_hash('admin123'), role='admin', name='Administrator')
        db.session.add(admin)
        db.session.commit()
        print("Admin created. Email: admin@gmail.com Password: admin123")
    app.run(debug=True, host='0.0.0.0', port=5000)
