#!/usr/bin/env python3
"""
Database Migration Script for Face Recognition Attendance System
Run this script to add new columns to the Timesheet table
"""

import os
import sys
from datetime import datetime
from sqlalchemy import inspect, text

# Add the current directory to path so we can import from app
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db
    from app import Timesheet, Employee, User
except ImportError as e:
    print(f"❌ Error importing app: {e}")
    print("Make sure you're running this script from the same directory as app.py")
    sys.exit(1)

def print_separator():
    """Print a separator line"""
    print("=" * 60)

def check_column_exists(table_name, column_name):
    """Check if a column exists in the table"""
    inspector = inspect(db.engine)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns

def add_column_if_not_exists(table_name, column_name, column_type):
    """Add a column to a table if it doesn't exist"""
    if not check_column_exists(table_name, column_name):
        try:
            with db.engine.connect() as conn:
                conn.execute(text(f'ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}'))
                conn.commit()
            print(f"  ✅ Added column: {column_name} ({column_type})")
            return True
        except Exception as e:
            print(f"  ❌ Failed to add {column_name}: {e}")
            return False
    else:
        print(f"  ⏭️  Column already exists: {column_name}")
        return False

def migrate_timesheet_table():
    """Add all new columns to Timesheet table"""
    print("\n📋 Migrating Timesheet table...")
    
    new_columns = [
        # Confidence scores
        ('signin_confidence', 'FLOAT DEFAULT 0.0'),
        ('signout_confidence', 'FLOAT DEFAULT 0.0'),
        
        # Face quality metrics
        ('signin_face_quality', 'FLOAT DEFAULT 0.0'),
        ('signout_face_quality', 'FLOAT DEFAULT 0.0'),
        
        # Liveness detection
        ('signin_liveness_passed', 'BOOLEAN DEFAULT 0'),
        ('signout_liveness_passed', 'BOOLEAN DEFAULT 0'),
        
        # Face encoding storage (optional - for future use)
        ('signin_face_encoding', 'TEXT'),
        ('signout_face_encoding', 'TEXT'),
        
        # Timestamps for face detection
        ('signin_detected_at', 'DATETIME'),
        ('signout_detected_at', 'DATETIME'),
        
        # Additional metadata
        ('signin_face_location', 'TEXT'),  # JSON string of face coordinates
        ('signout_face_location', 'TEXT'),
        ('face_recognition_version', 'VARCHAR(20) DEFAULT "1.0"'),
    ]
    
    added_count = 0
    for col_name, col_type in new_columns:
        if add_column_if_not_exists('timesheet', col_name, col_type):
            added_count += 1
    
    return added_count

def migrate_employee_table():
    """Add new columns to Employee table (optional)"""
    print("\n📋 Migrating Employee table...")
    
    new_columns = [
        # Store face encoding for faster matching
        ('face_encoding', 'TEXT'),  # Stored as JSON string
        
        # Face quality of registered image
        ('registered_face_quality', 'FLOAT DEFAULT 0.0'),
        
        # Multiple face images support
        ('additional_images', 'TEXT'),  # JSON array of filenames
        
        # Face detection metadata
        ('face_detection_version', 'VARCHAR(20) DEFAULT "1.0"'),
        ('last_face_update', 'DATETIME'),
    ]
    
    added_count = 0
    for col_name, col_type in new_columns:
        if add_column_if_not_exists('employee', col_name, col_type):
            added_count += 1
    
    return added_count

def create_indexes():
    """Create indexes for better query performance"""
    print("\n📊 Creating indexes...")
    
    indexes = [
        ("idx_timesheet_confidence", "timesheet", "signin_confidence"),
        ("idx_timesheet_date_confidence", "timesheet", "date, signin_confidence"),
        ("idx_timesheet_liveness", "timesheet", "signin_liveness_passed"),
        ("idx_employee_face_quality", "employee", "registered_face_quality"),
    ]
    
    created_count = 0
    for index_name, table, columns in indexes:
        try:
            with db.engine.connect() as conn:
                conn.execute(text(f'CREATE INDEX IF NOT EXISTS {index_name} ON {table} ({columns})'))
                conn.commit()
            print(f"  ✅ Created index: {index_name}")
            created_count += 1
        except Exception as e:
            print(f"  ❌ Failed to create index {index_name}: {e}")
    
    return created_count

def update_existing_records():
    """Update existing records with default values"""
    print("\n🔄 Updating existing records...")
    
    try:
        # Update signin_confidence where it's NULL
        with db.engine.connect() as conn:
            result = conn.execute(
                text("UPDATE timesheet SET signin_confidence = 0.0 WHERE signin_confidence IS NULL")
            )
            conn.commit()
            print(f"  ✅ Updated {result.rowcount} records with default signin_confidence")
    except Exception as e:
        print(f"  ❌ Failed to update signin_confidence: {e}")
    
    try:
        # Update signout_confidence where it's NULL
        with db.engine.connect() as conn:
            result = conn.execute(
                text("UPDATE timesheet SET signout_confidence = 0.0 WHERE signout_confidence IS NULL")
            )
            conn.commit()
            print(f"  ✅ Updated {result.rowcount} records with default signout_confidence")
    except Exception as e:
        print(f"  ❌ Failed to update signout_confidence: {e}")
    
    try:
        # Set face_recognition_version for existing records
        with db.engine.connect() as conn:
            result = conn.execute(
                text("UPDATE timesheet SET face_recognition_version = '1.0' WHERE face_recognition_version IS NULL")
            )
            conn.commit()
            print(f"  ✅ Updated {result.rowcount} records with face_recognition_version")
    except Exception as e:
        print(f"  ❌ Failed to update face_recognition_version: {e}")

def backup_database():
    """Create a backup of the database before migration"""
    print("\n💾 Creating database backup...")
    
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    if not os.path.isabs(db_path):
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_path)
    
    if os.path.exists(db_path):
        backup_path = db_path + f'.backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        try:
            import shutil
            shutil.copy2(db_path, backup_path)
            print(f"  ✅ Database backed up to: {backup_path}")
            return backup_path
        except Exception as e:
            print(f"  ❌ Failed to create backup: {e}")
            return None
    else:
        print(f"  ⚠️ Database file not found at: {db_path}")
        return None

def verify_migration():
    """Verify that all columns were added successfully"""
    print("\n✅ Verifying migration...")
    
    inspector = inspect(db.engine)
    timesheet_columns = [col['name'] for col in inspector.get_columns('timesheet')]
    
    expected_columns = [
        'signin_confidence', 'signout_confidence',
        'signin_face_quality', 'signout_face_quality',
        'signin_liveness_passed', 'signout_liveness_passed',
        'signin_face_encoding', 'signout_face_encoding',
        'signin_detected_at', 'signout_detected_at',
        'signin_face_location', 'signout_face_location',
        'face_recognition_version'
    ]
    
    missing = []
    for col in expected_columns:
        if col not in timesheet_columns:
            missing.append(col)
    
    if missing:
        print(f"  ❌ Missing columns: {', '.join(missing)}")
        return False
    else:
        print("  ✅ All expected columns present in Timesheet table")
        return True

def main():
    """Main migration function"""
    print_separator()
    print("🔧 FACE RECOGNITION ATTENDANCE SYSTEM - DATABASE MIGRATION")
    print_separator()
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    print_separator()
    
    # Ask for confirmation
    response = input("\n⚠️  This will modify your database schema. Create backup? (y/n): ")
    if response.lower() == 'y':
        backup_path = backup_database()
        if backup_path:
            print("✅ Backup created successfully")
    else:
        print("⏭️  Skipping backup")
    
    # Run migrations
    with app.app_context():
        print_separator()
        
        # Migrate Timesheet table
        timesheet_added = migrate_timesheet_table()
        
        # Migrate Employee table
        employee_added = migrate_employee_table()
        
        # Create indexes
        indexes_created = create_indexes()
        
        # Update existing records
        update_existing_records()
        
        # Verify migration
        verification_passed = verify_migration()
        
        print_separator()
        print("\n📊 MIGRATION SUMMARY")
        print_separator()
        print(f"Timesheet table: {timesheet_added} new columns added")
        print(f"Employee table: {employee_added} new columns added")
        print(f"Indexes created: {indexes_created}")
        print(f"Verification: {'✅ PASSED' if verification_passed else '❌ FAILED'}")
        print_separator()
        
        if verification_passed:
            print("\n✅ Database migration completed successfully!")
            print("\nNext steps:")
            print("  1. Restart your Flask application")
            print("  2. Test the face recognition features")
            print("  3. Check the mismatch detection page for new metrics")
        else:
            print("\n❌ Migration completed with issues. Please check the errors above.")
        
        print_separator()

def rollback():
    """Rollback migration (remove added columns)"""
    print("\n⚠️  ROLLBACK MIGRATION")
    print("This will remove the added columns from the database.")
    response = input("Are you sure? This cannot be undone! (type 'YES' to confirm): ")
    
    if response != 'YES':
        print("Rollback cancelled.")
        return
    
    with app.app_context():
        inspector = inspect(db.engine)
        timesheet_columns = [col['name'] for col in inspector.get_columns('timesheet')]
        
        columns_to_remove = [
            'signin_confidence', 'signout_confidence',
            'signin_face_quality', 'signout_face_quality',
            'signin_liveness_passed', 'signout_liveness_passed',
            'signin_face_encoding', 'signout_face_encoding',
            'signin_detected_at', 'signout_detected_at',
            'signin_face_location', 'signout_face_location',
            'face_recognition_version'
        ]
        
        removed_count = 0
        for col in columns_to_remove:
            if col in timesheet_columns:
                try:
                    with db.engine.connect() as conn:
                        # SQLite doesn't support DROP COLUMN directly, need to recreate table
                        # This is a simplified version - for production, use a proper migration tool
                        conn.execute(text(f'ALTER TABLE timesheet DROP COLUMN {col}'))
                        conn.commit()
                    print(f"  ✅ Removed column: {col}")
                    removed_count += 1
                except Exception as e:
                    print(f"  ❌ Failed to remove {col}: {e}")
        
        print(f"\n✅ Rollback complete. Removed {removed_count} columns.")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Database migration for face recognition system')
    parser.add_argument('--rollback', action='store_true', help='Rollback migration')
    args = parser.parse_args()
    
    if args.rollback:
        rollback()
    else:
        main()