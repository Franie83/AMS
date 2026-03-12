import cv2
import sys
import os

print("Testing camera access...")
print(f"Python version: {sys.version}")
print(f"OpenCV version: {cv2.__version__}")

try:
    # Try different camera indices
    for i in range(3):
        print(f"\nTrying camera index {i}...")
        cap = cv2.VideoCapture(i)
        
        if cap.isOpened():
            print(f"✅ Camera {i} opened successfully")
            ret, frame = cap.read()
            if ret and frame is not None:
                print(f"✅ Frame captured: {frame.shape}")
                cap.release()
                print(f"Camera {i} is working!")
                sys.exit(0)
            else:
                print(f"❌ Camera {i} opened but failed to capture frame")
                cap.release()
        else:
            print(f"❌ Camera {i} failed to open")
    
    print("\n❌ No working camera found")
    
except Exception as e:
    print(f"❌ Error: {e}")

input("\nPress Enter to exit...")