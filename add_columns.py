# add_columns.py
from app import app, db
from sqlalchemy import text
import sys

def add_columns():
    with app.app_context():
        try:
            print("🔧 Starting database migration...")
            
            # Add mda_attendance_link column
            try:
                db.session.execute(text('ALTER TABLE user ADD COLUMN mda_attendance_link VARCHAR(500)'))
                print("✅ Added column: mda_attendance_link")
            except Exception as e:
                if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                    print("ℹ️ Column mda_attendance_link already exists")
                else:
                    print(f"⚠️ Error adding mda_attendance_link: {e}")
            
            # Add credentials column
            try:
                db.session.execute(text('ALTER TABLE user ADD COLUMN credentials TEXT'))
                print("✅ Added column: credentials")
            except Exception as e:
                if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                    print("ℹ️ Column credentials already exists")
                else:
                    print(f"⚠️ Error adding credentials: {e}")
            
            # Add created_at column
            try:
                db.session.execute(text('ALTER TABLE user ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP'))
                print("✅ Added column: created_at")
            except Exception as e:
                if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                    print("ℹ️ Column created_at already exists")
                else:
                    print(f"⚠️ Error adding created_at: {e}")
            
            # Add updated_at column
            try:
                db.session.execute(text('ALTER TABLE user ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP'))
                print("✅ Added column: updated_at")
            except Exception as e:
                if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                    print("ℹ️ Column updated_at already exists")
                else:
                    print(f"⚠️ Error adding updated_at: {e}")
            
            db.session.commit()
            print("\n✅ Database migration completed successfully!")
            
            # Verify columns
            print("\n📋 Verifying columns in user table:")
            result = db.session.execute(text("PRAGMA table_info(user)"))
            columns = result.fetchall()
            for col in columns:
                print(f"   - {col[1]} ({col[2]})")
            
        except Exception as e:
            print(f"\n❌ Migration error: {e}")
            db.session.rollback()
            sys.exit(1)

if __name__ == "__main__":
    add_columns()