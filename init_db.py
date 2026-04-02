from app import app, db 
from werkzeug.security import generate_password_hash 
from app import User 
 
with app.app_context(): 
    db.create_all() 
    print("Database tables created!") 
 
    # Check if superadmin exists 
    if not User.query.filter_by(email='sadmin@gmail.com').first(): 
        superadmin = User( 
            email='sadmin@gmail.com', 
            password_hash=generate_password_hash('sadmin123'), 
            role='superadmin', 
            name='Super Administrator', 
            mda='SYSTEM' 
        ) 
        db.session.add(superadmin) 
        print("û Super Admin created: sadmin@gmail.com / sadmin123") 
 
    # Check if admin exists 
    if not User.query.filter_by(email='admin@gmail.com').first(): 
        admin = User( 
            email='admin@gmail.com', 
            password_hash=generate_password_hash('admin123'), 
            role='admin', 
            name='Administrator', 
            mda='ADMIN' 
        ) 
        db.session.add(admin) 
        print("û Admin created: admin@gmail.com / admin123") 
 
    db.session.commit() 
    print("Database initialization complete!") 
