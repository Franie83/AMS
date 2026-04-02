# init_database.py
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("Initializing Attendance System Database...")
print("=" * 50)

try:
    from app import app, db
    from werkzeug.security import generate_password_hash
    
    with app.app_context():
        print("📦 Creating database tables...")
        db.create_all()
        print("✅ Database tables created successfully!")
        
        # Import models after db is created
        from app import User, Employee, Timesheet
        
        # Create super admin
        print("\n👑 Creating Super Admin...")
        if not User.query.filter_by(email='sadmin@gmail.com').first():
            superadmin = User(
                email='sadmin@gmail.com',
                password_hash=generate_password_hash('sadmin123'),
                role='superadmin',
                name='Super Administrator',
                mda='SYSTEM'
            )
            db.session.add(superadmin)
            db.session.commit()
            print("✅ Super Admin created: sadmin@gmail.com / sadmin123")
        else:
            print("⚠️ Super Admin already exists")
        
        # Create admin
        print("\n🛡️ Creating Admin...")
        if not User.query.filter_by(email='admin@gmail.com').first():
            admin = User(
                email='admin@gmail.com',
                password_hash=generate_password_hash('admin123'),
                role='admin',
                name='Administrator',
                mda='ADMIN'
            )
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin created: admin@gmail.com / admin123")
        else:
            print("⚠️ Admin already exists")
        
        # Verify tables exist
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        print(f"\n📋 Tables in database: {', '.join(tables)}")
        
        print("\n" + "=" * 50)
        print("✅ Database initialization complete!")
        
except Exception as e:
    print(f"\n❌ Error: {e}")
    import traceback
    traceback.print_exc()

input("\nPress Enter to exit...")