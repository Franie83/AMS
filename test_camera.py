import cv2
import sys

def test_camera():
    print("Testing camera access...")
    cap = cv2.VideoCapture(0)
    
    if not cap.isOpened():
        print("❌ Camera failed to open!")
        return False
    
    ret, frame = cap.read()
    if ret:
        print("✅ Camera working! Frame captured")
        print(f"Frame size: {frame.shape}")
        cap.release()
        return True
    else:
        print("❌ Camera opened but failed to capture frame")
        cap.release()
        return False

if __name__ == "__main__":
    test_camera()