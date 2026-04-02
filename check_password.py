import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

print("=" * 60)
print("Checking Database Passwords")
print("=" * 60)

conn = sqlite3.connect('attendance.db')
c = conn.cursor()

# Get the sadmin user
c.execute("SELECT id, email, password_hash FROM user WHERE email = 'sadmin@gmail.com'")
user = c.fetchone()

if user:
    print(f"\nUser found: {user[1]}")
    print(f"Password hash: {user[2][:50]}...")
    
    # Test the password
    test_password = 'sadmin123'
    if check_password_hash(user[2], test_password):
        print(f"✓ Password '{test_password}' is correct")
    else:
        print(f"✗ Password '{test_password}' is INCORRECT")
        
        # Generate a new hash
        new_hash = generate_password_hash(test_password)
        print(f"\nNew hash: {new_hash[:50]}...")
        
        # Update the password
        c.execute("UPDATE user SET password_hash = ? WHERE email = ?", (new_hash, 'sadmin@gmail.com'))
        conn.commit()
        print("✓ Updated password hash")
        
        # Verify new hash
        c.execute("SELECT password_hash FROM user WHERE email = 'sadmin@gmail.com'")
        new_user = c.fetchone()
        if check_password_hash(new_user[0], test_password):
            print("✓ Verification successful!")
        else:
            print("✗ Verification failed!")
else:
    print("User not found!")

# Also fix admin
c.execute("SELECT id, email, password_hash FROM user WHERE email = 'admin@gmail.com'")
admin = c.fetchone()
if admin:
    test_password = 'admin123'
    if not check_password_hash(admin[2], test_password):
        new_hash = generate_password_hash(test_password)
        c.execute("UPDATE user SET password_hash = ? WHERE email = ?", (new_hash, 'admin@gmail.com'))
        print("✓ Updated admin password")

conn.commit()
conn.close()

print("\n" + "=" * 60)
print("Database fixed!")
print("\nLogin with:")
print("  sadmin@gmail.com / sadmin123")
print("  admin@gmail.com / admin123")
print("=" * 60)