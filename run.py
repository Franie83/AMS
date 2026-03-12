# run.py - Entry point for the compiled executable with proper path handling
import os
import sys
import webbrowser
import threading
import time
import traceback

def get_base_path():
    """Get the base path whether running as script or exe"""
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        return os.path.dirname(sys.executable)
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))

def setup_environment():
    """Setup the environment paths and change to correct directory"""
    base_path = get_base_path()
    
    # Change to base directory
    os.chdir(base_path)
    
    # Add base path to Python path if not already there
    if base_path not in sys.path:
        sys.path.insert(0, base_path)
    
    return base_path

def check_files(base_path):
    """Check if all required files exist"""
    required_paths = {
        'templates': os.path.join(base_path, 'templates'),
        'app.py': os.path.join(base_path, 'app.py'),
    }
    
    all_good = True
    for name, path in required_paths.items():
        exists = os.path.exists(path)
        print(f"  📁 {name}: {'✅' if exists else '❌'} - {path}")
        if not exists:
            all_good = False
    
    return all_good

# Setup paths
base_path = setup_environment()

print("=" * 60)
print("🚀 Attendance Management System")
print("=" * 60)
print(f"\n📁 Base directory: {base_path}")
print(f"📁 Current directory: {os.getcwd()}")
print(f"🐍 Python: {sys.executable if not getattr(sys, 'frozen', False) else 'Compiled EXE'}")

# Check required files
print("\n📋 Checking required files:")
files_ok = check_files(base_path)

if not files_ok:
    print("\n❌ ERROR: Some required files are missing!")
    print("   The executable might be in the wrong location.")
    print("   Please make sure all template files are in the correct directory.")
    input("\nPress Enter to exit...")
    sys.exit(1)

try:
    # Import the app
    print("\n📦 Importing application...")
    from app import app
    print("✅ Application imported successfully")
    
    # Create uploads folder if it doesn't exist
    uploads_dir = os.path.join(base_path, 'uploads')
    if not os.path.exists(uploads_dir):
        os.makedirs(uploads_dir)
        print(f"📁 Created uploads folder: {uploads_dir}")
    else:
        print(f"📁 Uploads folder exists: {uploads_dir}")
    
    # Check if database exists
    db_path = os.path.join(base_path, 'attendance.db')
    if os.path.exists(db_path):
        print(f"📁 Database found: {db_path}")
    else:
        print(f"📁 Database will be created on first use")
    
    def open_browser():
        """Open browser after a short delay"""
        time.sleep(2)
        try:
            webbrowser.open('http://localhost:5000')
            print("✅ Browser opened")
        except Exception as e:
            print(f"⚠️ Could not open browser: {e}")
    
    print("\n🌐 Starting server at: http://localhost:5000")
    print("📱 Opening browser automatically...")
    print("📝 Press CTRL+C to stop the server")
    print("=" * 60)
    
    # Start browser in a separate thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run the app
    app.run(debug=False, host='127.0.0.1', port=5000)
    
except Exception as e:
    print("\n" + "=" * 60)
    print("❌ APPLICATION ERROR")
    print("=" * 60)
    print(f"Error type: {type(e).__name__}")
    print(f"Error message: {e}")
    print("\nTraceback:")
    traceback.print_exc()
    print("\n" + "=" * 60)
    input("\nPress Enter to exit...")