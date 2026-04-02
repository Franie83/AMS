# attendance_system.spec
# -*- mode: python ; coding: utf-8 -*-


import sys
import os


# Set paths to current directory
current_dir = os.path.dirname(os.path.abspath(__file__))


a = Analysis(
    ['run.py'],
    pathex=[current_dir],
    binaries=[],
    datas=[
        (os.path.join(current_dir, 'templates'), 'templates'),
        (os.path.join(current_dir, 'static'), 'static'),
        (os.path.join(current_dir, 'uploads'), 'uploads'),
        (
            r'C:\Users\USER\Documents\apps\AMS\venv39\lib\site-packages\face_recognition_models\models',
            'face_recognition_models/models'
        ),
    ],
    hiddenimports=[
        'flask',
        'flask_sqlalchemy',
        'flask_login',
        'flask_wtf',
        'wtforms',
        'werkzeug',
        'cv2',
        'face_recognition',
        'PIL',
        'PIL.Image',
        'numpy',
        'pandas',
        'reportlab',
        'imagehash',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)


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
)


# Create the COLLECT directory for the application
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AttendanceSystem',
)