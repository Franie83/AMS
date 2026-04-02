import os
import sys
import traceback

# Set debug mode
os.environ['FLASK_ENV'] = 'development'
os.environ['FLASK_DEBUG'] = '1'

# Add current directory to path
sys.path.insert(0, os.getcwd())

print("Starting Flask with debug mode...")
print("=" * 60)

try:
    from app import app
    
    # Enable debug mode
    app.debug = True
    app.config['DEBUG'] = True
    
    print("✓ App imported with debug mode")
    print("\nNow try logging in at http://127.0.0.1:5000")
    print("The error will appear here in the console")
    print("=" * 60)
    
    app.run(host='127.0.0.1', port=5000, debug=True)
    
except Exception as e:
    print(f"\n❌ Error: {e}")
    traceback.print_exc()