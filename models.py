# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import secrets

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    phoneNumber = db.Column(db.String(20), primary_key=True)
    fullName = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='User')
    
    # Password reset fields - UNIQUE constraint removed for SQLite compatibility
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)

    # Password reset methods
    def generate_reset_token(self):
        """Generate a secure reset token valid for 1 hour"""
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()
        return self.reset_token

    def verify_reset_token(self, token):
        """Verify if token is valid and not expired"""
        return (self.reset_token == token and 
                self.reset_token_expiry and 
                self.reset_token_expiry > datetime.utcnow())

    def clear_reset_token(self):
        """Clear token after use"""
        self.reset_token = None
        self.reset_token_expiry = None
        db.session.commit()


class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.String(50), primary_key=True)
    userPhoneNumber = db.Column(
        db.String(20),
        db.ForeignKey('users.phoneNumber'),
        nullable=False
    )
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    videoUrl = db.Column(db.String(500))
    resolutionVideoUrl = db.Column(db.String(500))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    status = db.Column(db.String(20), default='Pending')
    timestamp = db.Column(db.Integer, default=lambda: int(datetime.now().timestamp()))

    # MDA forwarding fields
    mda_user_id = db.Column(
        db.String(20),
        db.ForeignKey('users.phoneNumber'),
        nullable=True
    )
    mda_assigned = db.Column(db.String(100))

    # who originally forwarded it away (hide from this user)
    forwarded_from_user = db.Column(db.String(20), nullable=True)

    submitter = db.relationship(
        'User',
        foreign_keys=[userPhoneNumber],
        lazy='joined'
    )
    forwarded_to = db.relationship(
        'User',
        foreign_keys=[mda_user_id],
        lazy='joined',
        uselist=False
    )


class AuditTrail(db.Model):
    __tablename__ = 'audit_trail'

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(
        db.String(50),
        db.ForeignKey('reports.id'),
        nullable=False
    )

    action = db.Column(db.String(50), nullable=False)       # 'submitted', 'forwarded', etc.
    actor_name = db.Column(db.String(120), nullable=False)  # who did it
    from_name = db.Column(db.String(120))
    to_name = db.Column(db.String(120))
    to_phone = db.Column(db.String(20))

    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    report = db.relationship('Report', backref='history')