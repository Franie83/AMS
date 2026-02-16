from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

from models import db, User, Report, AuditTrail
from sqlalchemy import or_, text
import os
import sys
import tempfile

# ========== NEW: Path handling for executable ==========
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    BASE_DIR = os.path.dirname(sys.executable)
    # Use AppData for database persistence (writable location)
    APP_DATA = os.path.join(os.environ.get('LOCALAPPDATA', BASE_DIR), 'EdoVoice')
    INSTANCE_PATH = os.path.join(APP_DATA, 'instance')
    # Use temp folder for video uploads
    UPLOAD_FOLDER = os.path.join(tempfile.gettempdir(), 'EdoVoice_uploads')
else:
    # Running as script during development
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    INSTANCE_PATH = os.path.join(BASE_DIR, 'instance')
    UPLOAD_FOLDER = 'static/uploads/videos'

# Create necessary folders
os.makedirs(INSTANCE_PATH, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# ======================================================

# 1. APP FIRST
app = Flask(__name__)
app.config['SECRET_KEY'] = 'edovoice-secret-2025-change-in-prod'
# ========== UPDATED: Database path ==========
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(INSTANCE_PATH, "edovoice.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Attach models.db to this app
db.init_app(app)

# 2. VIDEO CONFIG
# ========== UPDATED: Upload folder path ==========
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'avi', 'mkv', 'webm'}


def allowed_video_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS


# HELPERS
def get_user(phone):
    return User.query.get(phone)


def login_required(f):
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_phone' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles):
    def decorator(f):
        from functools import wraps

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_phone' not in session:
                return redirect(url_for('login'))
            user = get_user(session['user_phone'])
            if user and user.role not in roles:
                flash('Access denied', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


@app.template_filter('datetimeformat')
def datetimeformat(value):
    return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M')


# USER API ROUTES
@app.route('/api/users', methods=['POST'])
@login_required
@role_required('SuperAdmin')
def api_create_user():
    data = request.json
    if not data or get_user(data['phoneNumber']):
        return jsonify({'error': 'Invalid data or user exists'}), 400
    user = User(
        phoneNumber=data['phoneNumber'],
        fullName=data['fullName'],
        password=generate_password_hash(data['password']),
        role=data['role'],
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/users/<phone>', methods=['PUT'])
@login_required
@role_required('SuperAdmin')
def api_update_user(phone):
    user = User.query.get_or_404(phone)
    data = request.json
    if not data:
        return jsonify({'error': 'No JSON data'}), 400
    user.fullName = data['fullName']
    user.role = data['role']
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/users/<phone>', methods=['DELETE'])
@login_required
@role_required('SuperAdmin')
def api_delete_user(phone):
    if phone == '07000000001':
        return jsonify({'error': 'Cannot delete system admin'}), 403
    user = User.query.get_or_404(phone)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/reports/<report_id>', methods=['DELETE'])
@login_required
@role_required('SuperAdmin')
def delete_report(report_id):
    report = Report.query.get_or_404(report_id)

    # Optional: delete attached videos from disk
    for path in [report.videoUrl, report.resolutionVideoUrl]:
        if path:
            # Convert URL to filesystem path
            fs_path = path.replace('/static/uploads/videos/', '')
            full_path = os.path.join(app.config['UPLOAD_FOLDER'], fs_path)
            if os.path.exists(full_path):
                try:
                    os.remove(full_path)
                except Exception as e:
                    print(f"Failed to delete file {full_path}: {e}")

    db.session.delete(report)
    db.session.commit()
    return jsonify({'success': True})


# REPORT APIs
@app.route('/api/reports/<report_id>/status', methods=['POST'])
@login_required
@role_required('SuperAdmin', 'Admin')
def update_status(report_id):
    report = Report.query.get_or_404(report_id)
    data = request.json
    new_status = data['status']

    # If moving AWAY from Completed, delete the resolution video (after-video)
    if report.status == 'Completed' and new_status in ['Pending', 'In Progress']:
        if report.resolutionVideoUrl:
            # Convert URL to filesystem path
            fs_path = report.resolutionVideoUrl.replace('/static/uploads/videos/', '')
            full_path = os.path.join(app.config['UPLOAD_FOLDER'], fs_path)
            if os.path.exists(full_path):
                try:
                    os.remove(full_path)
                    print(f"🗑️ Deleted resolution video: {full_path}")
                except Exception as e:
                    print(f"⚠️ Failed to delete resolution video: {e}")
            report.resolutionVideoUrl = None

    # When setting to "Completed", return video prompt flag
    if new_status == 'Completed':
        report.status = 'Completed'
        db.session.commit()
        return jsonify(
            {
                'success': True,
                'status': 'Completed',
                'prompt_resolution_video': True,
            }
        )

    # Normal status change
    report.status = new_status
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/reports/<report_id>/resolution-video', methods=['POST'])
@login_required
@role_required('SuperAdmin', 'Admin')
def upload_resolution_video(report_id):
    report = Report.query.get_or_404(report_id)

    video_file = request.files.get('resolutionVideo')
    if not video_file or video_file.filename == '':
        return jsonify({'error': 'No video file provided'}), 400

    if not allowed_video_file(video_file.filename):
        return jsonify({'error': 'Invalid video format'}), 400

    try:
        ext = video_file.filename.rsplit('.', 1)[1].lower()
        filename = secure_filename(
            f"resolution_{report_id}_{int(datetime.now().timestamp())}.{ext}"
        )
        video_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        video_file.save(video_path)

        # Store relative path in database
        report.resolutionVideoUrl = f"/static/uploads/videos/{filename}"
        report.status = 'Completed'
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Upload error: {str(e)}")
        return jsonify({'error': 'File save failed'}), 500


# MAIN ROUTES
@app.route('/')
def index():
    return redirect(url_for('register'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        phone = request.form['phoneNumber']
        password = request.form['password']
        full_name = request.form['fullName']
        if get_user(phone):
            flash('Phone number already registered', 'error')
            return render_template('register.html')
        user = User(
            phoneNumber=phone,
            fullName=full_name,
            password=generate_password_hash(password),
            role='User',
        )
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form['phoneNumber']
        password = request.form['password']
        user = get_user(phone)
        if user and check_password_hash(user.password, password):
            session['user_phone'] = phone
            session['user_name'] = user.fullName
            session['user_role'] = user.role
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ========== PASSWORD RESET ROUTES ==========
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle password reset requests"""
    if request.method == 'POST':
        phone = request.form.get('phoneNumber', '').strip()
        
        if not phone or not phone.isdigit() or len(phone) != 11:
            flash('Please enter a valid 11-digit phone number', 'error')
            return render_template('forgot_password.html')
        
        user = get_user(phone)
        
        # Always show same message for security (don't reveal if user exists)
        if user:
            # Generate reset token
            token = user.generate_reset_token()
            
            # In production, send SMS via Africa's Talking, Twilio, etc.
            # For demo, we'll log to console and show on screen
            reset_link = url_for('reset_password', token=token, _external=True)
            print(f"\n🔐 PASSWORD RESET LINK for {phone}: {reset_link}\n")
            
            # Flash different messages based on environment
            if app.debug:
                flash(f'🔐 DEMO MODE: Reset link: {reset_link}', 'success')
            else:
                flash('✅ Password reset link has been sent to your phone via SMS', 'success')
        else:
            # Still show success message for security
            flash('✅ If this phone number exists, a reset link will be sent', 'success')
        
        return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password using token"""
    # Find user with this token
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or not user.verify_reset_token(token):
        flash('Invalid or expired reset link. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        
        # Validate password
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('reset_password.html', token=token)
        
        if password != confirm:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
        
        # Update password
        user.password = generate_password_hash(password)
        user.clear_reset_token()  # Remove token after use
        
        flash('✅ Password reset successful! Please login with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)


@app.route('/resend-reset-link', methods=['POST'])
def resend_reset_link():
    """Resend password reset link (API endpoint)"""
    phone = request.json.get('phoneNumber', '')
    user = get_user(phone)
    
    if user:
        token = user.generate_reset_token()
        reset_link = url_for('reset_password', token=token, _external=True)
        
        # Log for demo
        print(f"\n🔐 NEW RESET LINK for {phone}: {reset_link}\n")
        
        return jsonify({
            'success': True,
            'message': 'Reset link resent successfully',
            'debug_link': reset_link if app.debug else None
        })
    
    return jsonify({'success': False, 'error': 'User not found'}), 404
# ========== END PASSWORD RESET ROUTES ==========


@app.route('/dashboard')
@login_required
def dashboard():
    user = get_user(session['user_phone'])
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status')
    search = request.args.get('search', '')

    query = Report.query

    # SuperAdmin: sees everything
    if user.role == 'SuperAdmin':
        pass

    # User: only own reports, excluding ones they forwarded away
    elif user.role == 'User':
        query = query.filter(
            Report.userPhoneNumber == user.phoneNumber,
            text(
                "forwarded_from_user IS NULL "
                "OR forwarded_from_user != :me"
            ),
        ).params(me=user.phoneNumber)

    # Admin: reports in their category or assigned to them, excluding ones they forwarded away
    elif user.role == 'Admin':
        query = query.filter(
            or_(
                Report.category == user.fullName,
                Report.mda_user_id == user.phoneNumber,
            ),
            text(
                "forwarded_from_user IS NULL "
                "OR forwarded_from_user != :me"
            ),
        ).params(me=user.phoneNumber)

    if status:
        query = query.filter_by(status=status)
    if search:
        query = query.filter(
            or_(
                Report.description.contains(search),
                Report.category.contains(search),
            )
        )

    reports = query.order_by(Report.timestamp.desc()).paginate(
        page=page, per_page=10, error_out=False
    )

    # report.history is available via backref on AuditTrail.report

    admin_users = (
        db.session.query(User)
        .filter(User.role == 'Admin')
        .order_by(User.fullName)
        .all()
    )

    return render_template('dashboard.html', reports=reports, admin_users=admin_users)


@app.route('/new-report', methods=['GET', 'POST'])
@login_required
def new_report():
    admin_users = (
        db.session.query(User)
        .filter(User.role == 'Admin')
        .order_by(User.fullName)
        .all()
    )

    if request.method == 'POST':
        try:
            video_file = request.files.get('video')

            video_url = None
            if video_file and video_file.filename != '':
                video_file.seek(0)
                file_size = len(video_file.read())
                video_file.seek(0)

                if allowed_video_file(video_file.filename):
                    ext = (
                        video_file.filename.rsplit('.', 1)[1].lower()
                        if '.' in video_file.filename
                        else 'mp4'
                    )
                    filename = secure_filename(
                        f"{session['user_phone']}_{int(datetime.now().timestamp())}.{ext}"
                    )
                    video_path = os.path.join(
                        app.config['UPLOAD_FOLDER'], filename
                    )
                    video_file.save(video_path)
                    video_url = f"/static/uploads/videos/{filename}"
                else:
                    return jsonify({'error': 'Invalid video format'}), 400
            else:
                return jsonify({'error': 'No video file received'}), 400

            selected_admin_name = request.form.get('category')
            if not selected_admin_name:
                return jsonify(
                    {
                        'error': 'Issue Category (MDA admin) is required',
                    }
                ), 400

            report = Report(
                id=f"report-{int(datetime.now().timestamp())}",
                userPhoneNumber=session['user_phone'],
                category=selected_admin_name,
                description=request.form.get('description', ''),
                videoUrl=video_url,
                latitude=float(request.form.get('latitude'))
                if request.form.get('latitude')
                else None,
                longitude=float(request.form.get('longitude'))
                if request.form.get('longitude')
                else None,
                status='Pending',
            )
            db.session.add(report)

            # AUDIT: submitted
            audit = AuditTrail(
                report_id=report.id,
                action='submitted',
                actor_name=session.get('user_name') or session['user_phone'],
                from_name=session.get('user_name') or session['user_phone'],
                to_name=selected_admin_name,  # MDA/category at first hop
                timestamp=datetime.utcnow()
            )
            db.session.add(audit)

            db.session.commit()

            return jsonify({'success': True, 'report_id': report.id})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500

    return render_template('report_form.html', admin_users=admin_users)


@app.route('/report/<report_id>')
@login_required
def report_card(report_id):
    report = Report.query.get_or_404(report_id)
    current_user = get_user(session['user_phone'])

    # load full audit history for this report
    history = AuditTrail.query.filter_by(report_id=report.id) \
        .order_by(AuditTrail.timestamp.asc()).all()

    return render_template(
        'report_card.html',
        report=report,
        current_user=current_user,
        history=history,
    )


@app.route('/map')
@login_required
def map_view():
    reports = Report.query.all()

    if reports:
        lats = [r.latitude for r in reports if r.latitude]
        lons = [r.longitude for r in reports if r.longitude]

        if lats and lons and len(set(lons)) > 1:
            min_lat, max_lat = min(lats) - 0.01, max(lats) + 0.01
            min_lon, max_lon = min(lons) - 0.01, max(lons) + 0.01
        else:
            min_lat, max_lat = 6.5244 - 0.5, 6.5244 + 0.5
            min_lon, max_lon = 5.6254 - 0.5, 5.6254 + 0.5
    else:
        min_lat, max_lat = 6.5244 - 0.5, 6.5244 + 0.5
        min_lon, max_lon = 5.6254 - 0.5, 5.6254 + 0.5

    return render_template(
        'map.html',
        reports=reports,
        min_lat=min_lat,
        max_lat=max_lat,
        min_lon=min_lon,
        max_lon=max_lon,
    )


@app.route('/api/reports/<report_id>/forward-mda', methods=['POST'])
@login_required
@role_required('SuperAdmin', 'Admin')
def forward_to_mda(report_id):
    report = Report.query.get_or_404(report_id)
    data = request.json

    mda_user_id = data.get('mda_user_id')
    mda_text = data.get('mda', '').strip()

    current = get_user(session['user_phone'])

    # If the current user is NOT SuperAdmin, they should lose visibility
    if current.role != 'SuperAdmin':
        report.forwarded_from_user = current.phoneNumber

    # 🔹 previous handler BEFORE this forward (category first time, then last assigned)
    previous_handler_name = report.mda_assigned or report.category

    # Resolve target MDA / handler
    target_name = None
    target_phone = None

    if mda_user_id:
        mda_user = db.session.get(User, mda_user_id)
        if not mda_user or mda_user.role not in ['Admin', 'SuperAdmin']:
            return jsonify({'error': 'Invalid MDA admin user'}), 400

        target_name = mda_user.fullName
        target_phone = mda_user.phoneNumber

        # update report destination
        report.mda_user_id = mda_user.phoneNumber
        report.mda_assigned = mda_user.fullName
    elif mda_text:
        target_name = mda_text
        report.mda_assigned = mda_text
    else:
        return jsonify({'error': 'MDA is required'}), 400

    report.status = 'In Progress'

    # AUDIT TRAIL ENTRY (forward movement)
    audit = AuditTrail(
        report_id=report.id,
        action='forwarded',
        actor_name=current.fullName,       # who clicked Forward (e.g. test)
        from_name=previous_handler_name,   # where it was before (e.g. Blossom)
        to_name=target_name,               # where it is going now (e.g. Eminence)
        to_phone=target_phone,
        timestamp=datetime.utcnow()
    )
    db.session.add(audit)

    db.session.commit()

    return jsonify(
        {
            'success': True,
            'mda': report.mda_assigned,
            'mda_user_id': getattr(report, 'mda_user_id', None),
        }
    )


@app.route('/users')
@login_required
def users():
    user = get_user(session['user_phone'])

    # Only SuperAdmin and Admin can view users
    if user.role not in ['SuperAdmin', 'Admin']:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))

    search = request.args.get('search', '').strip()
    query = User.query

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                User.fullName.ilike(like),
                User.phoneNumber.ilike(like),
            )
        )

    users = query.order_by(User.fullName).all()
    return render_template('users.html', users=users, search=search, current_user=user)


@app.errorhandler(404)
@app.errorhandler(500)
def handle_error(error):
    if (
        request.headers.get('Accept') == 'application/json'
        or request.is_json
    ):
        return (
            jsonify({'error': str(error), 'success': False}),
            (error.code or 500),
        )
    return render_template('error.html'), (error.code or 500)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print(f"📁 Database location: {app.config['SQLALCHEMY_DATABASE_URI']}")
        print(f"📁 Upload folder: {app.config['UPLOAD_FOLDER']}")

        # ===== UPDATED: Add password reset columns to users table (without UNIQUE) =====
        try:
            # Check users table columns
            user_result = db.session.execute(
                db.text('PRAGMA table_info(users)')
            ).fetchall()
            user_columns = [row[1] for row in user_result]

            if 'reset_token' not in user_columns:
                db.session.execute(
                    db.text(
                        'ALTER TABLE users ADD COLUMN reset_token VARCHAR(100)'
                    )
                )
                db.session.commit()
                print("✅ Added reset_token column to users table")

            if 'reset_token_expiry' not in user_columns:
                db.session.execute(
                    db.text(
                        'ALTER TABLE users ADD COLUMN reset_token_expiry DATETIME'
                    )
                )
                db.session.commit()
                print("✅ Added reset_token_expiry column to users table")

        except Exception as e:
            print(f"⚠️ Users table migration note: {e}")
        # ===== END UPDATED =====

        try:
            result = db.session.execute(
                db.text('PRAGMA table_info(reports)')
            ).fetchall()
            columns = [row[1] for row in result]

            if 'resolutionVideoUrl' not in columns:
                db.session.execute(
                    db.text(
                        'ALTER TABLE reports '
                        'ADD COLUMN resolutionVideoUrl VARCHAR(500)'
                    )
                )
                db.session.commit()

            if 'mda_user_id' not in columns:
                db.session.execute(
                    db.text(
                        'ALTER TABLE reports '
                        'ADD COLUMN mda_user_id VARCHAR(20)'
                    )
                )
                db.session.commit()

            if 'mda_assigned' not in columns:
                db.session.execute(
                    db.text(
                        'ALTER TABLE reports '
                        'ADD COLUMN mda_assigned VARCHAR(100)'
                    )
                )
                db.session.commit()

            if 'forwarded_from_user' not in columns:
                db.session.execute(
                    db.text(
                        'ALTER TABLE reports '
                        'ADD COLUMN forwarded_from_user VARCHAR(20)'
                    )
                )
                db.session.commit()

        except Exception as e:
            print(f"✅ Database OK (or migration skipped): {e}")

        if not db.session.get(User, '07000000001'):
            superadmin = User(
                phoneNumber='07000000001',
                fullName='Super Admin',
                password=generate_password_hash('super123'),
                role='SuperAdmin',
            )
            db.session.add(superadmin)
            db.session.commit()
            print("👑 SuperAdmin created")

    print('=' * 50)
    print('🚀 EdoVoice Server Ready!')
    print('=' * 50)
    print(f'📍 Database: {app.config["SQLALCHEMY_DATABASE_URI"]}')
    print(f'📍 Uploads: {app.config["UPLOAD_FOLDER"]}')
    print(f'📍 Web: http://127.0.0.1:5000')
    print(f'🔐 Password reset: http://127.0.0.1:5000/forgot-password')
    print('=' * 50)
    
    # When running as exe, don't use debug mode
    if getattr(sys, 'frozen', False):
        app.run(debug=False, host='127.0.0.1', port=5000)
    else:
        app.run(debug=True)