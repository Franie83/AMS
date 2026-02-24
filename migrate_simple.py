#!/usr/bin/env python3
"""
Simple Database Migration Script
Run this to add new columns to Timesheet table
"""

import os
import sys
from sqlalchemy import inspect, text

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, db
except ImportError:
    print("❌ Error: Make sure you're running this from the same directory as app.py")
    sys.exit(1)

def migrate():
    """Add new columns to Timesheet table"""
    with app.app_context():
        inspector = inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('timesheet')]
        
        new_columns = [
            ('signin_confidence', 'FLOAT DEFAULT 0.0'),
            ('signout_confidence', 'FLOAT DEFAULT 0.0'),
            ('signin_face_quality', 'FLOAT DEFAULT 0.0'),
            ('signout_face_quality', 'FLOAT DEFAULT 0.0'),
            ('signin_liveness_passed', 'BOOLEAN DEFAULT 0'),
            ('signout_liveness_passed', 'BOOLEAN DEFAULT 0'),
        ]
        
        print("📊 Migrating Timesheet table...")
        added = 0
        
        for col_name, col_type in new_columns:
            if col_name not in columns:
                try:
                    with db.engine.connect() as conn:
                        conn.execute(text(f'ALTER TABLE timesheet ADD COLUMN {col_name} {col_type}'))
                        conn.commit()
                    print(f"  ✅ Added: {col_name}")
                    added += 1
                except Exception as e:
                    print(f"  ❌ Error adding {col_name}: {e}")
            else:
                print(f"  ⏭️  Already exists: {col_name}")
        
        print(f"\n✅ Migration complete! Added {added} new columns.")
        print("\nRestart your Flask app to use the new features.")

if __name__ == '__main__':
    migrate()