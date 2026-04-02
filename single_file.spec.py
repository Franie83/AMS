# -*- mode: python ; coding: utf-8 -*-

import os
import sys

# Collect all data files
datas = []

# Add templates directory
for root, dirs, files in os.walk('templates'):
    for file in files:
        full_path = os.path.join(root, file)
        dest_path = os.path.join('templates', os.path.relpath(full_path, 'templates'))
        datas.append((full_path, dest_path))

# Add static directory
for root, dirs, files in os.walk('static'):
    for file in files:
        full_path = os.path.join(root, file)
        dest_path = os.path.join('static', os.path.relpath(full_path, 'static'))
        datas.append((full_path, dest_path))

# Add uploads directory
for root, dirs, files in os.walk('uploads'):
    for file in files:
        full_path = os.path.join(root, file)
        dest_path = os.path.join('uploads', os.path.relpath(full_path, 'uploads'))
        datas.append((full_path, dest_path))

a = Analysis(
    ['run.py'],
    pathex=[],
    binaries=[],
    datas=datas,
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