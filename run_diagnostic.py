# run_diagnostic.py - Diagnostic version to find path issues
import os
import sys
import traceback

def debug_print(msg):
    print(f"[DEBUG] {msg}")

def check_path(path):
    exists = os.path.exists(path)
    debug_print(f"Checking {path}: {'✅ FOUND' if exists else '❌ NOT FOUND'}")
    return exists

print("=" * 60)
print("ATTENDANCE SYSTEM - DIAGNOSTIC MODE")
print("=" * 60)

# Check current paths
debug_print(f"Current directory: {os.getcwd()}")
debug_print(f"Executable path: {sys.executable}")
debug_print(f"Script directory: {os.path.dirname(os.path.abspath(__file__))}")

# Check for critical files and folders
print("\n📁 CHECKING CRITICAL PATHS:")
check_path('templates')
check_path('templates/layout.html')
check_path('templates/live_attendance.html')
check_path('uploads')
check_path('attendance.db')
check_path('app.py')

# Try to import the app
print("\n📦 IMPORTING APP:")
try:
    from app import app
    debug_print("App imported successfully!")
    
    # List all routes
    print("\n📋 REGISTERED ROUTES:")
    for rule in app.url_map.iter_rules():
        print(f"  {rule}")
        
except Exception as e:
    print(f"\n❌ ERROR IMPORTING APP: {e}")
    traceback.print_exc()

print("\n" + "=" * 60)
print("Diagnostic complete. Press Enter to exit...")
input()