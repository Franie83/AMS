import os
import sys
import subprocess
import shutil

print("=" * 70)
print("Building Attendance Management System")
print("=" * 70)

# Clean previous builds
for folder in ['dist', 'build', '__pycache__']:
    if os.path.exists(folder):
        shutil.rmtree(folder)
        print(f"Removed {folder}")

# Build command
cmd = [
    sys.executable, "-m", "PyInstaller",
    "--onefile",
    "--windowed",
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
    "--hidden-import=pandas",
    "--hidden-import=reportlab",
    "--hidden-import=imagehash",
    "--collect-all=flask",
    "--collect-all=flask_sqlalchemy",
    "--collect-all=flask_login",
    "--collect-all=cv2",
    "--collect-all=face_recognition",
    "--collect-all=PIL",
    "--clean",
    "--noconfirm",
    "run.py"
]

print("\nBuilding executable...")
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
        print(f"\nExecutable: {os.path.abspath(exe_path)}")
        print(f"Size: {size_mb:.2f} MB")
    else:
        print("\nExecutable not found!")
else:
    print("\nBuild failed!")

print("\nPress Enter to exit...")
input()