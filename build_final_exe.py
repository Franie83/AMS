import os
import sys
import subprocess
import shutil

def build_executable():
    """Build the executable with Python 3.9"""
    
    print("=" * 70)
    print("Building Attendance Management System")
    print(f"Python version: {sys.version}")
    print("=" * 70)
    
    # Clean previous builds
    print("\nCleaning previous builds...")
    for folder in ['dist', 'build', '__pycache__']:
        if os.path.exists(folder):
            shutil.rmtree(folder)
            print(f"  Removed {folder}")
    
    for file in os.listdir('.'):
        if file.endswith('.spec'):
            os.remove(file)
            print(f"  Removed {file}")
    
    # Build command with onefile and windowed
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",  # No console window
        "--name=AttendanceSystem",
        "--add-data=templates;templates",
        "--add-data=static;static",
        "--add-data=uploads;uploads",
        "--hidden-import=flask",
        "--hidden-import=flask_sqlalchemy",
        "--hidden-import=flask_login",
        "--hidden-import=flask_wtf",
        "--hidden-import=wtforms",
        "--hidden-import=werkzeug",
        "--hidden-import=cv2",
        "--hidden-import=face_recognition",
        "--hidden-import=face_recognition_models",
        "--hidden-import=PIL",
        "--hidden-import=PIL.Image",
        "--hidden-import=numpy",
        "--hidden-import=numpy.core",
        "--hidden-import=numpy.core._methods",
        "--hidden-import=numpy.lib",
        "--hidden-import=pandas",
        "--hidden-import=reportlab",
        "--hidden-import=imagehash",
        "--hidden-import=sqlalchemy",
        "--hidden-import=jinja2",
        "--hidden-import=markupsafe",
        "--hidden-import=click",
        "--hidden-import=itsdangerous",
        "--collect-all=flask",
        "--collect-all=flask_sqlalchemy",
        "--collect-all=flask_login",
        "--collect-all=cv2",
        "--collect-all=face_recognition",
        "--collect-all=PIL",
        "--exclude-module=tkinter",
        "--exclude-module=matplotlib",
        "--exclude-module=scipy",
        "--exclude-module=IPython",
        "--clean",
        "--noconfirm",
        "run.py"
    ]
    
    print("\n📦 Building executable...")
    print("This may take 5-10 minutes...")
    print("-" * 70)
    
    result = subprocess.run(cmd)
    
    if result.returncode == 0:
        exe_path = os.path.join("dist", "AttendanceSystem.exe")
        if os.path.exists(exe_path):
            size_mb = os.path.getsize(exe_path) / (1024 * 1024)
            print("\n" + "=" * 70)
            print("✓ BUILD SUCCESSFUL!")
            print("=" * 70)
            print(f"\n📁 Executable: {os.path.abspath(exe_path)}")
            print(f"📊 Size: {size_mb:.2f} MB")
            return True
        else:
            print("\n✗ Executable not found!")
            return False
    else:
        print("\n✗ Build failed!")
        return False

def create_distribution_package():
    """Create the final distribution package"""
    
    print("\n" + "=" * 70)
    print("Creating Distribution Package")
    print("=" * 70)
    
    package_dir = "Attendance_System_Final"
    if os.path.exists(package_dir):
        shutil.rmtree(package_dir)
    os.makedirs(package_dir)
    
    # Copy executable
    shutil.copy("dist/AttendanceSystem.exe", package_dir)
    print("✓ Copied AttendanceSystem.exe")
    
    # Create database initialization script
    with open(os.path.join(package_dir, "init_db.py"), "w") as f:
        f.write('''import sqlite3
import os
from werkzeug.security import generate_password_hash

def init_database():
    db_path = 'attendance.db'
    
    if os.path.exists(db_path):
        print("Database already exists. Checking...")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
        if cursor.fetchone():
            print("Database is ready.")
            conn.close()
            return
        conn.close()
        os.remove(db_path)
    
    print("Creating fresh database...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
    CREATE TABLE user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email VARCHAR(150) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user',
        name VARCHAR(150),
        phone VARCHAR(50),
        mda VARCHAR(150),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE employee (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employeeid VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(150) NOT NULL,
        mda VARCHAR(150),
        email VARCHAR(150),
        phone VARCHAR(50),
        role VARCHAR(50) DEFAULT 'employee',
        registered_image VARCHAR(300),
        registered_face_quality FLOAT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE timesheet (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_id INTEGER NOT NULL,
        employee_name VARCHAR(150),
        mda VARCHAR(150),
        registered_image VARCHAR(300),
        signin_image VARCHAR(300),
        signout_image VARCHAR(300),
        date DATE,
        time_in TIME,
        time_out TIME,
        reg_signin_match BOOLEAN DEFAULT 1,
        reg_signout_match BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        signin_confidence FLOAT DEFAULT 0,
        signout_confidence FLOAT DEFAULT 0
    )
    ''')
    
    # Insert default users
    cursor.execute('INSERT INTO user (email, password_hash, role, name, mda) VALUES (?, ?, ?, ?, ?)',
        ('sadmin@gmail.com', generate_password_hash('sadmin123'), 'superadmin', 'Super Administrator', 'SYSTEM'))
    cursor.execute('INSERT INTO user (email, password_hash, role, name, mda) VALUES (?, ?, ?, ?, ?)',
        ('admin@gmail.com', generate_password_hash('admin123'), 'admin', 'Administrator', 'ADMIN'))
    
    conn.commit()
    conn.close()
    print("Database created with default users!")

if __name__ == "__main__":
    init_database()
    print("\\nLogin credentials:")
    print("  Super Admin: sadmin@gmail.com / sadmin123")
    print("  Admin: admin@gmail.com / admin123")
    input("\\nPress Enter to exit...")
''')
    print("✓ Created init_db.py")
    
    # Create launcher
    with open(os.path.join(package_dir, "Start_Attendance.bat"), "w") as f:
        f.write('''@echo off
title Attendance Management System
color 0A
echo ========================================
echo    Attendance Management System v1.0
echo ========================================
echo.
cd /d "%~dp0"

if not exist attendance.db (
    echo First run - Creating database...
    python init_db.py
    echo.
)

echo Starting Attendance System...
start http://127.0.0.1:5000
AttendanceSystem.exe
''')
    print("✓ Created Start_Attendance.bat")
    
    # Create silent launcher
    with open(os.path.join(package_dir, "Start_Silent.vbs"), "w") as f:
        f.write('''CreateObject("WScript.Shell").Run "Start_Attendance.bat", 0, False
''')
    print("✓ Created silent launcher")
    
    # Create README
    with open(os.path.join(package_dir, "README.txt"), "w") as f:
        f.write('''Attendance Management System v1.0
========================================

INSTALLATION:
1. Extract all files to any folder
2. Double-click "Start_Attendance.bat"

LOGIN:
Super Admin: sadmin@gmail.com / sadmin123
Admin: admin@gmail.com / admin123

REQUIREMENTS:
- Windows 7/8/10/11 (64-bit)
- Webcam

For support, contact your administrator.
''')
    print("✓ Created README.txt")
    
    print("\n" + "=" * 70)
    print("✓ DISTRIBUTION PACKAGE READY!")
    print("=" * 70)
    print(f"\n📁 Location: {os.path.abspath(package_dir)}")
    print("\nTo distribute: Zip the folder and share.")
    
    return True

if __name__ == "__main__":
    if build_executable():
        create_distribution_package()
        print("\n" + "=" * 70)
        print("✅ COMPLETE! Ready for distribution.")
        print("=" * 70)
    else:
        print("\n❌ Build failed. Check errors above.")