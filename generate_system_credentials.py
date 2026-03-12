#!/usr/bin/env python
"""
System Onboarding Tool
Collects hardware credentials needed for system registration
"""

import subprocess
import platform
import sys

def print_header():
    print("=" * 50)
    print("     SYSTEM ONBOARDING CREDENTIALS")
    print("=" * 50)
    print()

def get_mac_windows():
    try:
        result = subprocess.check_output('getmac /v /fo list', shell=True).decode('utf-8', errors='ignore')
        for line in result.split('\n'):
            if 'Physical Address' in line:
                parts = line.split(':')
                if len(parts) > 1:
                    return parts[1].strip()
    except:
        pass
    return "NOT DETECTED"

def get_cpu_windows():
    try:
        result = subprocess.check_output('wmic cpu get processorid', shell=True).decode('utf-8', errors='ignore')
        for line in result.split('\n'):
            line = line.strip()
            if line and not line.startswith('ProcessorId'):
                return line
    except:
        pass
    return "NOT DETECTED"

def get_serial_windows():
    try:
        result = subprocess.check_output('wmic bios get serialnumber', shell=True).decode('utf-8', errors='ignore')
        for line in result.split('\n'):
            line = line.strip()
            if line and not line.startswith('SerialNumber') and line != 'To be filled by O.E.M.':
                return line
    except:
        pass
    return "NOT DETECTED"

def main():
    print_header()
    
    if platform.system() == 'Windows':
        mac = get_mac_windows()
        cpu = get_cpu_windows()
        serial = get_serial_windows()
        
        print("[1] MAC ADDRESS:")
        print(f"    {mac}")
        print()
        
        print("[2] CPU ID:")
        print(f"    {cpu}")
        print()
        
        print("[3] MOTHERBOARD SERIAL:")
        print(f"    {serial}")
        print()
        
        print("[4] COMPUTER NAME (for reference):")
        print(f"    {platform.node()}")
        print()
        
        print("=" * 50)
        print("COPY THESE 3 VALUES TO REGISTER THIS SYSTEM:")
        print("-" * 40)
        print("1. MAC Address")
        print("2. CPU ID")
        print("3. Motherboard Serial")
        print("=" * 50)
        print()
        print("Send these 3 values to your System Administrator")
    else:
        print("This script is designed for Windows systems only")
        sys.exit(1)

if __name__ == "__main__":
    main()
    input("\nPress Enter to exit...")