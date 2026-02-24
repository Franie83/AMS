#!/usr/bin/env python
"""
Launcher script for Attendance Management System
This script runs the Flask app and handles the execution environment
"""

import os
import sys
import webbrowser
import threading
import time
from pathlib import Path

# Add the current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def open_browser():
    """Open browser after a short delay"""
    time.sleep(2)
    webbrowser.open('http://127.0.0.1:5000')

if __name__ == '__main__':
    # Import the app here to avoid circular imports
    try:
        from app import app
        
        # Create necessary directories
        os.makedirs('uploads', exist_ok=True)
        os.makedirs('instance', exist_ok=True)
        
        # Start browser thread
        threading.Thread(target=open_browser, daemon=True).start()
        
        # Run the app
        app.run(debug=False, host='127.0.0.1', port=5000)
        
    except Exception as e:
        print(f"Error starting application: {e}")
        input("Press Enter to exit...")
        sys.exit(1)