# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['run_app.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('uploads', 'uploads'),
    ],
    hiddenimports=[
        'flask', 'flask_sqlalchemy', 'flask_login', 'flask_wtf',
        'wtforms', 'werkzeug', 'jinja2', 'markupsafe', 'click',
        'itsdangerous', 'sqlalchemy', 'greenlet', 'typing_extensions',
        'face_recognition', 'dlib', 'face_recognition_models',
        'PIL', 'PIL.Image', 'PIL.ImageDraw', 'numpy', 'scipy',
        'skimage', 'cv2', 'imagehash', 'pandas', 'openpyxl', 'reportlab',
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