# admin_license_tool.py - UPDATED
import json
import hashlib
from datetime import datetime, timedelta

# 🔐 Must match run.py and protection.py SECRET_KEY
SECRET_KEY = "MY_SUPER_SECRET_KEY_2026"

def generate_license():
    print("=" * 60)
    print("Attendance System - License Generator")
    print("=" * 60)

    customer_name = input("\nCustomer name: ").strip()
    if not customer_name:
        customer_name = "Customer"

    print("\nPaste the hardware fingerprint from customer:")
    fingerprint = input(">>> ").strip()

    if not fingerprint or len(fingerprint) != 64:
        print("\n❌ Invalid fingerprint! Must be 64 hex characters.")
        return

    expiry_input = input("\nExpiry days (default 365): ").strip()
    expiry_days = int(expiry_input) if expiry_input else 365

    expiry_date = (datetime.now() + timedelta(days=expiry_days)).strftime('%Y-%m-%d')

    license_data = {
        'hardware_fingerprint': fingerprint,
        'customer': customer_name,
        'issued': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'expiry': expiry_date,
        'version': '1.0'
    }

    # 🔐 Create secure signature compatible with run.py and protection.py
    data_string = json.dumps(license_data, sort_keys=True)
    signature = hashlib.sha256((data_string + SECRET_KEY).encode()).hexdigest()
    license_data['signature'] = signature

    filename = "license.dat"

    with open(filename, 'w') as f:
        json.dump(license_data, f, indent=2)

    print("\n" + "=" * 60)
    print("✅ LICENSE CREATED SUCCESSFULLY!")
    print("=" * 60)
    print(f"📁 File: {filename}")
    print(f"👤 Customer: {customer_name}")
    print(f"📅 Expires: {expiry_date}")
    print("\n📧 Send this file to the customer.")
    print("📍 They must place it in the app folder.")
    print("=" * 60)

def check_license():
    filename = input("\nLicense file path: ").strip()

    try:
        with open(filename, 'r') as f:
            data = json.load(f)

        print("\n" + "=" * 60)
        print("LICENSE DETAILS")
        print("=" * 60)
        print(f"👤 Customer: {data.get('customer')}")
        print(f"📅 Issued: {data.get('issued')}")
        print(f"📅 Expires: {data.get('expiry')}")
        print(f"🔢 Version: {data.get('version')}")
        print(f"🖥️ Hardware: {data.get('hardware_fingerprint')[:32]}...")

        signature = data.get('signature')
        if not signature:
            print("\n❌ Invalid license format (no signature)")
            return

        license_copy = {
            "hardware_fingerprint": data.get("hardware_fingerprint"),
            "customer": data.get("customer"),
            "issued": data.get("issued"),
            "expiry": data.get("expiry"),
            "version": data.get("version")
        }

        data_string = json.dumps(license_copy, sort_keys=True)
        expected_sig = hashlib.sha256((data_string + SECRET_KEY).encode()).hexdigest()

        if signature != expected_sig:
            print("\n❌ License corrupted or tampered!")
            return

        expiry = datetime.strptime(data['expiry'], '%Y-%m-%d')
        if datetime.now() > expiry:
            print("\n⚠️ LICENSE EXPIRED")
        else:
            days_left = (expiry - datetime.now()).days
            print(f"\n✅ Valid for {days_left} more days")

    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    while True:
        print("\n" + "=" * 60)
        print("Attendance System - Admin Tools")
        print("=" * 60)
        print("1. Generate new license")
        print("2. Check license file")
        print("3. Exit")

        choice = input("\nChoose (1-3): ").strip()

        if choice == '1':
            generate_license()
        elif choice == '2':
            check_license()
        elif choice == '3':
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()