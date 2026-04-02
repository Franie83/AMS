import os
import sys
import webbrowser
import threading
import time

def get_base_path():
    """Get the base path for the application"""
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        return os.path.dirname(sys.executable)
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))

# Set the base path
base_path = get_base_path()
os.chdir(base_path)

print("=" * 60)
print("🚀 Attendance Management System")
print("=" * 60)
print(f"📁 Base directory: {base_path}")
print(f"🐍 Python: {'Compiled EXE' if getattr(sys, 'frozen', False) else 'Script'}")

# Check if required directories exist
required_dirs = ['templates', 'static', 'uploads']
missing = []
for dir_name in required_dirs:
    dir_path = os.path.join(base_path, dir_name)
    if not os.path.exists(dir_path):
        missing.append(dir_name)
        print(f"  📁 {dir_name}: ❌ - {dir_path}")
    else:
        print(f"  📁 {dir_name}: ✅")

if missing:
    print("\n❌ ERROR: Some required directories are missing!")
    print("   The executable might be in the wrong location.")
    print(f"   Expected location: {base_path}")
    print("\n   Please ensure all files are in the correct directory:")
    for dir_name in missing:
        print(f"   - {dir_name}/ folder")
    input("\nPress Enter to exit...")
    sys.exit(1)

print("\n✅ All required files found!")
print("\n📋 Starting application...")

# Add the base path to Python path
sys.path.insert(0, base_path)

# Import the app
try:
    from app import app
except ImportError as e:
    print(f"❌ Failed to import app: {e}")
    print(f"   Python path: {sys.path}")
    input("\nPress Enter to exit...")
    sys.exit(1)

def open_browser():
    """Open browser after a short delay"""
    time.sleep(2)
    webbrowser.open('http://127.0.0.1:5000')

if __name__ == '__main__':
    # Start browser in a separate thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run the app
    print(f"\n🌐 Server starting at: http://127.0.0.1:5000")
    print("   Press Ctrl+C to stop the server\n")
    app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)