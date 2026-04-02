# run.py - FINAL VERSION WITH PROTECTION (EXE + SCRIPT SAFE)

import os
import sys
import webbrowser
import threading
import time
import json
import hashlib
from datetime import datetime

def resource_path(relative_path):
    """Get absolute path to resource (works for dev & PyInstaller EXE)"""
    try:
        base_path = sys._MEIPASS  # PyInstaller temp folder
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def get_base_path():
    """Get writable base path (important for DB)"""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)  # EXE folder
    else:
        return os.path.dirname(os.path.abspath(__file__))

# ============ PROTECTION SYSTEM ============

class LicenseProtection:
    """Hardware-based license protection"""
    
    SECRET_KEY = "MY_SUPER_SECRET_KEY_2026"
    
    def __init__(self):
        self.license_file = os.path.join(get_base_path(), "license.dat")
    
    def get_hardware_fingerprint(self):
        """Get unique hardware fingerprint"""
        try:
            import wmi
            c = wmi.WMI()
            
            hardware = []
            
            cpu = c.Win32_Processor()[0]
            if cpu.ProcessorId:
                hardware.append(f"CPU:{cpu.ProcessorId}")
            
            board = c.Win32_BaseBoard()[0]
            if board.SerialNumber and board.SerialNumber != 'To be filled by O.E.M.':
                hardware.append(f"MB:{board.SerialNumber}")
            
            disk = c.Win32_DiskDrive()[0]
            if disk.SerialNumber:
                hardware.append(f"DISK:{disk.SerialNumber}")
            
            bios = c.Win32_BIOS()[0]
            if bios.SerialNumber:
                hardware.append(f"BIOS:{bios.SerialNumber}")
            
            fingerprint_string = "|".join(sorted(hardware))
            return hashlib.sha256(fingerprint_string.encode()).hexdigest()
            
        except Exception:
            import platform
            import uuid
            data = f"{platform.node()}{platform.processor()}{uuid.getnode()}"
            return hashlib.sha256(data.encode()).hexdigest()
    
    def check_license(self):
        """Check if license exists and is valid"""
        if not os.path.exists(self.license_file):
            return False, "License file not found"
        
        try:
            with open(self.license_file, 'r') as f:
                license_data = json.load(f)

            signature = license_data.get('signature')
            if not signature:
                return False, "Invalid license format"

            # Recreate exact structure used during signing
            license_copy = {
                "hardware_fingerprint": license_data.get("hardware_fingerprint"),
                "customer": license_data.get("customer"),
                "issued": license_data.get("issued"),
                "expiry": license_data.get("expiry"),
                "version": license_data.get("version")
            }

            # 🔐 SIGNATURE CHECK using SECRET_KEY
            data_string = json.dumps(license_copy, sort_keys=True)
            expected_sig = hashlib.sha256((data_string + self.SECRET_KEY).encode()).hexdigest()

            if signature != expected_sig:
                return False, "Corrupted or tampered license"

            # ===== CHECK EXPIRY =====
            expiry = datetime.strptime(license_data['expiry'], '%Y-%m-%d')
            if datetime.now() > expiry:
                return False, f"License expired on {license_data['expiry']}"

            # ===== CHECK HARDWARE =====
            current = self.get_hardware_fingerprint()
            if current != license_data['hardware_fingerprint']:
                return False, "License is for different computer"

            return True, f"License valid (expires {license_data['expiry']})"

        except Exception as e:
            return False, f"License error: {str(e)}"
    
    def show_activation(self):
        """Show activation screen"""
        print("\n" + "=" * 60)
        print("  LICENSE ACTIVATION REQUIRED")
        print("=" * 60)
        
        fingerprint = self.get_hardware_fingerprint()
        if fingerprint:
            print("\nYour Hardware Fingerprint:")
            print(fingerprint)
            print("\n" + "=" * 60)
            print("To activate this software:")
            print("1. Copy the fingerprint above")
            print("2. Email it to: support@yourcompany.com")
            print("3. You will receive a license.dat file")
            print("4. Place license.dat in this folder")
            print("5. Restart the application")
            print("=" * 60)
            
            try:
                import subprocess
                subprocess.run(['clip.exe'], input=fingerprint.encode(), check=True)
                print("\n✓ Fingerprint copied to clipboard!")
            except:
                pass
        else:
            print("\nCould not read hardware information")
        
        input("\nPress Enter to exit...")
        sys.exit(1)
    
    def protect(self):
        """Main protection check"""
        print("=" * 60)
        print("  Attendance Management System")
        print("  License Check")
        print("=" * 60)
        
        valid, message = self.check_license()
        
        if valid:
            print(f"✓ {message}")
            print("=" * 60)
            return True
        else:
            print(f"✗ {message}")
            self.show_activation()
            return False

# ============ MAIN APPLICATION ============

BASE_PATH = get_base_path()
RESOURCE_BASE = resource_path("")

os.chdir(BASE_PATH)

print("=" * 60)
print("🚀 Attendance Management System")
print("=" * 60)
print(f"📁 Base directory: {BASE_PATH}")

# Run protection check FIRST
protection = LicenseProtection()
if not protection.protect():
    sys.exit(1)

# Check required folders
required_dirs = ['templates', 'static', 'uploads']
missing = []

for d in required_dirs:
    path = resource_path(d)
    if not os.path.exists(path):
        missing.append(d)
        print(f"  📁 {d}: ❌")
    else:
        print(f"  📁 {d}: ✅")

if missing:
    print("\n❌ Missing required folders:", missing)
    sys.exit(1)

print("\n✅ All required files found!")

# Add path for imports
sys.path.insert(0, BASE_PATH)

# Import app
try:
    from app import app, db, User
    from werkzeug.security import generate_password_hash
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)

# Fix Flask paths
app.template_folder = resource_path("templates")
app.static_folder = resource_path("static")

# Fix database location
DB_PATH = os.path.join(BASE_PATH, "attendance.db")

# Initialize DB
with app.app_context():
    try:
        if not os.path.exists(DB_PATH):
            print("\n📦 Creating database...")
            db.create_all()

            # Create default users
            if not User.query.filter_by(email='sadmin@gmail.com').first():
                db.session.add(User(
                    email='sadmin@gmail.com',
                    password_hash=generate_password_hash('sadmin123'),
                    role='superadmin',
                    name='Super Administrator',
                    mda='SYSTEM'
                ))
                print("  ✓ Super Admin created")

            if not User.query.filter_by(email='admin@gmail.com').first():
                db.session.add(User(
                    email='admin@gmail.com',
                    password_hash=generate_password_hash('admin123'),
                    role='admin',
                    name='Administrator',
                    mda='ADMIN'
                ))
                print("  ✓ Admin created")

            db.session.commit()
            print("✅ Default users created")

        else:
            print(f"\n📦 Database found: {DB_PATH}")

    except Exception as e:
        print(f"⚠️ Database error: {e}")

# Fix OpenCV threading issue
try:
    import cv2
    cv2.setNumThreads(0)
    print("✓ OpenCV configured")
except:
    pass

def open_browser():
    """Open browser after server starts"""
    time.sleep(2)
    webbrowser.open("http://127.0.0.1:5000")

if __name__ == '__main__':
    threading.Thread(target=open_browser, daemon=True).start()

    print("\n" + "=" * 60)
    print("🌐 Server running at: http://127.0.0.1:5000")
    print("📱 Press Ctrl+C to stop the server")
    print("=" * 60 + "\n")

    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)