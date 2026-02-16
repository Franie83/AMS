# build_final.py
import PyInstaller.__main__
import os
import shutil

def clean():
    for folder in ['dist', 'build', '__pycache__']:
        if os.path.exists(folder):
            shutil.rmtree(folder)

def build():
    print("=" * 60)
    print("🚀 Building EdoVoice with Python 3.9")
    print("=" * 60)
    
    args = [
        'app.py',
        '--name=EdoVoice',
        '--onefile',
        '--windowed',
        '--add-data', f'templates{os.pathsep}templates',
        '--add-data', f'static{os.pathsep}static',
        '--hidden-import=flask',
        '--hidden-import=flask_sqlalchemy',
        '--hidden-import=sqlalchemy',
        '--hidden-import=werkzeug',
        '--collect-all=flask',
        '--collect-all=flask_sqlalchemy',
        '--clean',
    ]
    
    try:
        PyInstaller.__main__.run(args)
        return True
    except Exception as e:
        print(f"❌ Build failed: {e}")
        return False

if __name__ == "__main__":
    clean()
    if build():
        print("\n✅ SUCCESS! Executable at: dist/EdoVoice.exe")