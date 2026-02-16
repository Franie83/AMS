# build_final_attempt.py
import PyInstaller.__main__
import os
import shutil

def clean():
    """Clean build artifacts"""
    for folder in ['dist', 'build', '__pycache__']:
        if os.path.exists(folder):
            shutil.rmtree(folder)
    for file in ['EdoVoice.spec']:
        if os.path.exists(file):
            os.remove(file)

def build():
    print("=" * 60)
    print("🚀 Building EdoVoice - Final Attempt")
    print("=" * 60)
    
    # Create hooks directory if it doesn't exist
    hooks_dir = 'hooks'
    if not os.path.exists(hooks_dir):
        os.makedirs(hooks_dir)
        print(f"📁 Created hooks directory: {hooks_dir}")
    
    # Create the hook file
    hook_content = '''# hook-flask.py
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files('flask')
hiddenimports = (
    collect_submodules('flask') +
    collect_submodules('werkzeug') +
    collect_submodules('jinja2') +
    collect_submodules('markupsafe') +
    collect_submodules('click') +
    collect_submodules('itsdangerous')
)
'''
    with open(os.path.join(hooks_dir, 'hook-flask.py'), 'w') as f:
        f.write(hook_content)
    print("✅ Created custom Flask hook")
    
    # PyInstaller command with additional hooks path
    args = [
        'app.py',
        '--name=EdoVoice',
        '--onefile',
        '--windowed',
        '--add-data', f'templates{os.pathsep}templates',
        '--add-data', f'static{os.pathsep}static',
        '--additional-hooks-dir', hooks_dir,
        '--hidden-import=flask',
        '--hidden-import=flask_sqlalchemy',
        '--hidden-import=sqlalchemy',
        '--hidden-import=sqlalchemy.ext.declarative',
        '--hidden-import=sqlalchemy.orm',
        '--hidden-import=werkzeug',
        '--hidden-import=werkzeug.security',
        '--hidden-import=werkzeug.utils',
        '--hidden-import=datetime',
        '--hidden-import=secrets',
        '--hidden-import=jinja2',
        '--hidden-import=jinja2.ext',
        '--hidden-import=markupsafe',
        '--hidden-import=click',
        '--hidden-import=itsdangerous',
        '--collect-all=flask',
        '--collect-all=flask_sqlalchemy',
        '--collect-all=werkzeug',
        '--collect-all=jinja2',
        '--collect-all=sqlalchemy',
        '--clean',
        '--noconfirm',
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
        print("\n" + "=" * 60)
        print("✅ BUILD SUCCESSFUL!")
        print("=" * 60)
        print("\n📁 Your executable is at: dist/EdoVoice.exe")
    else:
        print("\n❌ Build failed. Let's try a different tool...")

# If we get here, let's try auto-py-to-exe
print("\n" + "=" * 60)
print("🔄 Attempting alternative build with auto-py-to-exe")
print("=" * 60)
print("\nPlease run these commands manually:")
print("1. pip install auto-py-to-exe")
print("2. auto-py-to-exe")
print("\nIn the GUI that opens:")
print("- Select app.py as script location")
print("- Choose 'One File' option")
print("- Choose 'Window Based' (hide console)")
print("- Add templates and static folders in Additional Files")
print("- Click 'Convert .py to .exe'")