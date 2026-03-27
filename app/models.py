"""
Database Models for Policy-as-Code Platform
============================================
This module defines all SQLite database models using SQLAlchemy ORM.

Tables:
- User: Stores user information with role and department attributes
- Policy: Stores Rego policies with versioning support
- AuditLog: Records all authorization decisions for compliance
"""

from datetime import datetime
from app import db
import bcrypt


class User(db.Model):
    """
    User Model
    ==========
    Stores user credentials and attributes used for ABAC (Attribute-Based Access Control).
    
    Attributes:
        - id: Primary key
        - username: Unique username for login
        - password_hash: Bcrypt hashed password
        - role: User's role (admin, manager, employee)
        - department: User's department (engineering, hr, finance, etc.)
        - designation: User's job title
        - is_active: Whether user account is active
        - created_at: Account creation timestamp
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # ABAC Attributes - These are sent to OPA for policy evaluation
    role = db.Column(db.String(50), nullable=False, default='employee')
    department = db.Column(db.String(50), nullable=False, default='general')
    designation = db.Column(db.String(100), nullable=True)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_password(self, password):
        """
        Hash and store password using bcrypt.
        
        Args:
            password (str): Plain text password
        """
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password):
        """
        Verify password against stored hash.
        
        Args:
            password (str): Plain text password to verify
        
        Returns:
            bool: True if password matches, False otherwise
        """
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def to_dict(self):
        """
        Convert user object to dictionary for API responses.
        Excludes sensitive data like password hash.
        """
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'department': self.department,
            'designation': self.designation,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def get_attributes(self):
        """
        Get user attributes for OPA policy evaluation.
        These attributes are used in ABAC decisions.
        """
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'department': self.department,
            'designation': self.designation
        }
    
    def __repr__(self):
        return f'<User {self.username}>'


class Policy(db.Model):
    """
    Policy Model
    ============
    Stores Rego policies for OPA evaluation.
    Supports versioning and enable/disable functionality.
    
    Attributes:
        - id: Primary key
        - name: Policy identifier (unique)
        - description: Human-readable policy description
        - version: Policy version for tracking changes
        - policy_code: Rego policy code
        - is_active: Whether policy is currently enforced
        - created_by: User who created the policy
        - created_at: Policy creation timestamp
    """
    __tablename__ = 'policies'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    version = db.Column(db.String(20), nullable=False, default='1.0.0')
    policy_code = db.Column(db.Text, nullable=False)
    
    # Policy status
    is_active = db.Column(db.Boolean, default=True)
    
    # Audit fields
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    creator = db.relationship('User', backref=db.backref('policies', cascade='all, delete-orphan'))
    
    def to_dict(self):
        """Convert policy object to dictionary for API responses."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'policy_code': self.policy_code,
            'is_active': self.is_active,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<Policy {self.name} v{self.version}>'


class AuditLog(db.Model):
    """
    Audit Log Model
    ===============
    Records all authorization decisions for compliance and debugging.
    
    Attributes:
        - id: Primary key
        - user_id: User who made the request
        - username: Username (stored for historical reference)
        - action: Action attempted (read, write, delete)
        - resource: Resource accessed
        - decision: OPA decision (allow/deny)
        - reason: Explanation for the decision
        - ip_address: Client IP address
        - timestamp: When the decision was made
    """
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=True)
    username = db.Column(db.String(80), nullable=False)
    
    # Authorization request details
    action = db.Column(db.String(50), nullable=False)
    resource = db.Column(db.String(200), nullable=False)
    resource_type = db.Column(db.String(50), nullable=True)
    
    # Authorization decision
    decision = db.Column(db.String(10), nullable=False)  # 'allow' or 'deny'
    reason = db.Column(db.Text, nullable=True)
    
    # Context information
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)
    request_data = db.Column(db.Text, nullable=True)  # JSON string of request context
    
    # Timestamp
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        """Convert audit log to dictionary for API responses."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'action': self.action,
            'resource': self.resource,
            'resource_type': self.resource_type,
            'decision': self.decision,
            'reason': self.reason,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
    
    def __repr__(self):
        return f'<AuditLog {self.username} {self.action} {self.resource} -> {self.decision}>'
