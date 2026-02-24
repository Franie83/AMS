import sqlite3

# Connect to database
conn = sqlite3.connect('attendance.db')
cursor = conn.cursor()

# Check all employees
print("\n=== ALL EMPLOYEES ===")
cursor.execute('SELECT id, employeeid, name, email, phone, registered_image FROM employee ORDER BY id DESC')
results = cursor.fetchall()

if results:
    for r in results:
        print(f"ID: {r[0]}, EmpID: {r[1]}, Name: {r[2]}, Email: {r[3]}, Phone: {r[4]}, Image: {r[5]}")
else:
    print("No employees found")

# Check count
cursor.execute('SELECT COUNT(*) FROM employee')
count = cursor.fetchone()[0]
print(f"\nTotal employees: {count}")

# Check for test user specifically
cursor.execute("SELECT * FROM employee WHERE name LIKE '%test%' OR email LIKE '%test%'")
test_results = cursor.fetchall()
if test_results:
    print("\n=== TEST USER FOUND ===")
    for r in test_results:
        print(r)
else:
    print("\nNo test user found in database")

conn.close()