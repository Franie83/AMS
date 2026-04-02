import sqlite3
from werkzeug.security import generate_password_hash

print("=" * 60)
print("Fixing Passwords")
print("=" * 60)

db_path = 'attendance.db'
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Update passwords for all users
updates = [
    ('sadmin@gmail.com', 'sadmin123'),
    ('admin@gmail.com', 'admin123'),
]

for email, password in updates:
    new_hash = generate_password_hash(password)
    c.execute("UPDATE user SET password_hash = ? WHERE email = ?", (new_hash, email))
    print(f"✓ Updated password for {email}")

conn.commit()

# Verify passwords work
from werkzeug.security import check_password_hash

for email, password in updates:
    c.execute("SELECT password_hash FROM user WHERE email = ?", (email,))
    result = c.fetchone()
    if result:
        stored_hash = result[0]
        if check_password_hash(stored_hash, password):
            print(f"✓ Verification OK for {email}")
        else:
            print(f"✗ Verification FAILED for {email}")

conn.close()

print("\n" + "=" * 60)
print("Passwords fixed!")
print("\nLogin credentials:")
print("  Super Admin: sadmin@gmail.com / sadmin123")
print("  Admin: admin@gmail.com / admin123")
print("=" * 60)