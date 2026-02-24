import sqlite3

# Connect to database
conn = sqlite3.connect('attendance.db')
cursor = conn.cursor()

# Query all employees
cursor.execute('SELECT id, employeeid, name, email FROM employee')
results = cursor.fetchall()

print('\n=== ALL EMPLOYEE EMAILS ===')
print('ID\tEmpID\t\tName\t\t\tEmail')
print('-' * 60)

for row in results:
    print(f'{row[0]}\t{row[1]}\t{row[2][:15]:15}\t{row[3]}')

# Check for duplicates
print('\n=== CHECKING FOR DUPLICATES ===')
cursor.execute('''
    SELECT email, COUNT(*) as count 
    FROM employee 
    GROUP BY email 
    HAVING count > 1
''')
duplicates = cursor.fetchall()

if duplicates:
    print('Found duplicate emails:')
    for dup in duplicates:
        print(f'Email: {dup[0]} appears {dup[1]} times')
else:
    print('No duplicate emails found')

conn.close()