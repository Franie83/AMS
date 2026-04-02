# -*- mode: python ; coding: utf-8 -*-

import os
import sys

# Get the path to face_recognition_models
import face_recognition_models
face_recognition_models_path = os.path.dirname(face_recognition_models.__file__)

a = Analysis(
    ['run.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('static', 'static'),
        ('uploads', 'uploads'),
        (face_recognition_models_path, 'face_recognition_models'),
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
        'face_recognition_models',
        'PIL',
        'PIL.Image',
        'numpy',
        'numpy.core._methods',
        'numpy.lib',
        'pandas',
        'reportlab',
        'imagehash',
        'sqlalchemy',
        'jinja2',
        'markupsafe',
        'click',
        'itsdangerous',
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

# Create the COLLECT directory
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AttendanceSystem',
)