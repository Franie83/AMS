
# simple_test.py
import sys
import os

print("=" * 50)
print("SIMPLE TEST EXECUTABLE")
print("=" * 50)
print(f"Python version: {sys.version}")
print(f"Executable path: {sys.executable}")
print(f"Current directory: {os.getcwd()}")
print(f"Script directory: {os.path.dirname(os.path.abspath(__file__))}")

print("\nFiles in current directory:")
try:
    for f in os.listdir('.'):
        print(f"  {f}")
except Exception as e:
    print(f"Error listing files: {e}")

print("\n" + "=" * 50)
print("Test completed!")
print("=" * 50)

# Keep window open
input("\nPress Enter to exit...")