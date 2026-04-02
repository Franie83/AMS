# protection.py - UPDATED to match run.py method
import os
import json
import hashlib
from datetime import datetime

class LicenseProtection:
    """Hardware-based license protection"""

    SECRET_KEY = "MY_SUPER_SECRET_KEY_2026"

    def __init__(self):
        self.license_file = os.path.join(os.path.dirname(__file__), "license.dat")

    def get_hardware_fingerprint(self):
        """Generate unique hardware fingerprint - MATCHES run.py"""
        try:
            import wmi
            c = wmi.WMI()
            
            hardware = []
            
            cpu = c.Win32_Processor()[0]
            if cpu.ProcessorId:
                hardware.append(f"CPU:{cpu.ProcessorId}")
            
            board = c.Win32_BaseBoard()[0]
            if board.SerialNumber and board.SerialNumber != 'To be filled by O.E.M.':
                hardware.append(f"MB:{board.SerialNumber}")
            
            disk = c.Win32_DiskDrive()[0]
            if disk.SerialNumber:
                hardware.append(f"DISK:{disk.SerialNumber}")
            
            bios = c.Win32_BIOS()[0]
            if bios.SerialNumber:
                hardware.append(f"BIOS:{bios.SerialNumber}")
            
            fingerprint_string = "|".join(sorted(hardware))
            return hashlib.sha256(fingerprint_string.encode()).hexdigest()
            
        except Exception:
            # Fallback if WMI fails
            import platform
            import uuid
            data = f"{platform.node()}{platform.processor()}{uuid.getnode()}"
            return hashlib.sha256(data.encode()).hexdigest()

    def check_license(self):
        """Validate license file"""
        if not os.path.exists(self.license_file):
            return False, "License file missing"

        try:
            with open(self.license_file, 'r') as f:
                license_data = json.load(f)

            signature = license_data.get('signature')
            if not signature:
                return False, "Invalid license format"

            license_copy = {
                "hardware_fingerprint": license_data.get("hardware_fingerprint"),
                "customer": license_data.get("customer"),
                "issued": license_data.get("issued"),
                "expiry": license_data.get("expiry"),
                "version": license_data.get("version")
            }

            data_string = json.dumps(license_copy, sort_keys=True)
            expected_sig = hashlib.sha256((data_string + self.SECRET_KEY).encode()).hexdigest()

            if signature != expected_sig:
                return False, "Corrupted or tampered license"

            expiry = datetime.strptime(license_data['expiry'], '%Y-%m-%d')
            if datetime.now() > expiry:
                return False, f"License expired on {license_data['expiry']}"

            current = self.get_hardware_fingerprint()
            if current != license_data['hardware_fingerprint']:
                return False, "License is for different computer"

            return True, f"Valid until {license_data['expiry']}"

        except Exception as e:
            return False, f"License error: {e}"

    def protect(self):
        """Run license check before app starts"""
        valid, message = self.check_license()

        if valid:
            print(f"✅ License valid: {message}")
            return True
        else:
            print(f"❌ {message}")
            return False


if __name__ == "__main__":
    lp = LicenseProtection()
    print("\nHardware Fingerprint:\n")
    print(lp.get_hardware_fingerprint())