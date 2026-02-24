# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['run_app.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('uploads', 'uploads'),
        ('instance', 'instance'),
    ],
    hiddenimports=[
        'flask',
        'flask_sqlalchemy',
        'flask_login',
        'werkzeug',
        'PIL',
        'imagehash',
        'pandas',
        'reportlab',
        'cv2',
        'face_recognition',
        'numpy',
        'sqlalchemy',
        'wtforms',
        'email_validator',
        'openpyxl',
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
    console=True,  # Set to False to hide console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico'  # Optional: add your icon file
)