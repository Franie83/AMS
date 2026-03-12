@echo off
title Building Attendance System with Camera Fix
color 0A

echo ========================================
echo    Building with Camera Fix
echo ========================================
echo.

:: Activate virtual environment
call venv39\Scripts\activate

:: Create the spec file
echo Creating spec file...
python -c "
import os
spec_content = '''# -*- mode: python ; coding: utf-8 -*-

import os
import sys
from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs

# Get face_recognition models path
try:
    import face_recognition_models
    models_path = os.path.dirname(face_recognition_models.__file__)
except:
    models_path = None

# Get OpenCV path
try:
    import cv2
    opencv_path = os.path.dirname(cv2.__file__)
    print(f\"OpenCV path: {opencv_path}\")
except:
    opencv_path = None
    print(\"Warning: Could not find OpenCV path\")

a = Analysis(
    ['app.py'],
    pathex=['C:\\\\Users\\\\USER\\\\Documents\\\\apps\\\\AMS'],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('uploads', 'uploads'),
    ],
    hiddenimports=[
        'face_recognition',
        'face_recognition_models',
        'dlib',
        'PIL',
        'PIL._tkinter_finder',
        'cv2',
        'cv2.videoio',
        'numpy',
        'sqlalchemy',
        'flask',
        'flask_login',
        'flask_sqlalchemy',
        'flask_wtf',
        'wtforms',
        'pandas',
        'reportlab',
        'imagehash',
        'werkzeug',
        'email_validator',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'test', 'distutils', 'unittest'],
    noarchive=False,
    optimize=0
)

# Add face_recognition models if found
if models_path:
    a.datas.append((models_path, 'face_recognition_models'))

# Try to find and add OpenCV DLLs
if opencv_path and os.path.exists(opencv_path):
    # Look for DLLs in the opencv directory
    for file in os.listdir(opencv_path):
        if file.endswith('.dll'):
            a.binaries.append((os.path.join(opencv_path, file), '.'))

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AttendanceSystem',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None
)
'''

with open('attendance_camera_fix.spec', 'w') as f:
    f.write(spec_content)
print('✅ Spec file created')
"

:: Clean previous builds
echo.
echo Cleaning old builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist *.spec del /q *.spec

:: Create uploads folder
if not exist uploads mkdir uploads

:: Build with the spec file
echo.
echo Building executable with camera fixes...
echo.

pyinstaller attendance_camera_fix.spec

if %errorlevel% equ 0 (
    echo.
    echo ========================================
    echo    ✅ Build Successful!
    echo ========================================
    echo.
    echo Executable: dist\AttendanceSystem.exe
    
    :: Create run script
    echo @echo off > dist\run.bat
    echo title Attendance System >> dist\run.bat
    echo color 0A >> dist\run.bat
    echo. >> dist\run.bat
    echo echo ======================================== >> dist\run.bat
    echo echo    Starting Attendance System >> dist\run.bat
    echo echo ======================================== >> dist\run.bat
    echo echo. >> dist\run.bat
    echo echo Access at: http://localhost:5000 >> dist\run.bat
    echo echo. >> dist\run.bat
    echo AttendanceSystem.exe >> dist\run.bat
    echo pause >> dist\run.bat
    
    echo.
    echo Run script created: dist\run.bat
) else (
    echo.
    echo ========================================
    echo    ❌ Build Failed
    echo ========================================
)

pause