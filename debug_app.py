import sqlite3
from werkzeug.security import check_password_hash

print("Testing login...")

db_path = 'attendance.db'
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Check if users exist
c.execute("SELECT email, password_hash, role FROM user")
users = c.fetchall()
print(f"\nUsers in database: {len(users)}")
for user in users:
    print(f"  Email: {user[0]}, Role: {user[2]}")

# Test login
email = 'sadmin@gmail.com'
password = 'sadmin123'

c.execute("SELECT password_hash FROM user WHERE email = ?", (email,))
result = c.fetchone()

if result:
    stored_hash = result[0]
    if check_password_hash(stored_hash, password):
        print(f"\n✓ Login successful for {email}")
    else:
        print(f"\n✗ Invalid password for {email}")
else:
    print(f"\n✗ User {email} not found")

conn.close()