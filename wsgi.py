# wsgi.py
import sys
import os

# Add your project directory to the path
path = '/home/yourusername/AMS'  # Change 'yourusername' to your PythonAnywhere username
if path not in sys.path:
    sys.path.append(path)

# Import your Flask app
from app import app as application

# This is the standard WSGI convention
if __name__ == '__main__':
    application.run()