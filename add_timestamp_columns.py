# add_timestamp_columns.py
from app import app, db
from sqlalchemy import text
from datetime import datetime

def add_timestamp_columns():
    with app.app_context():
        try:
            print("🔧 Adding timestamp columns to user table...")
            
            # Add created_at column without default first
            try:
                db.session.execute(text('ALTER TABLE user ADD COLUMN created_at TIMESTAMP'))
                print("✅ Added column: created_at")
            except Exception as e:
                if "duplicate column name" in str(e).lower():
                    print("ℹ️ Column created_at already exists")
                else:
                    print(f"⚠️ Error adding created_at: {e}")
            
            # Add updated_at column without default first
            try:
                db.session.execute(text('ALTER TABLE user ADD COLUMN updated_at TIMESTAMP'))
                print("✅ Added column: updated_at")
            except Exception as e:
                if "duplicate column name" in str(e).lower():
                    print("ℹ️ Column updated_at already exists")
                else:
                    print(f"⚠️ Error adding updated_at: {e}")
            
            # Update existing records with current timestamp
            try:
                current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
                db.session.execute(text(f"UPDATE user SET created_at = '{current_time}' WHERE created_at IS NULL"))
                db.session.execute(text(f"UPDATE user SET updated_at = '{current_time}' WHERE updated_at IS NULL"))
                print("✅ Updated existing records with current timestamps")
            except Exception as e:
                print(f"⚠️ Could not update existing records: {e}")
            
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

if __name__ == "__main__":
    add_timestamp_columns()