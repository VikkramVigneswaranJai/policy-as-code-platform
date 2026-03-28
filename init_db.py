"""
Database Initialization Script
==============================
This script initializes the SQLite database with sample data for testing.

It creates:
- Sample users (admin, manager, employee)
- Sample policies (ABAC, RBAC, time-based)

Usage:
    python init_db.py

This script is idempotent - it can be run multiple times safely.
Existing users and policies will not be duplicated.
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app, db
from app.models import User, Policy

# Sample Rego policy code
SAMPLE_POLICIES = [
    {
        'name': 'main_authz_policy',
        'description': 'Main ABAC policy for authorization decisions. Implements role-based rules with department and time restrictions.',
        'version': '1.0.0',
        'policy_code': '''# Main Authorization Policy (ABAC)
# =================================
# This policy implements Attribute-Based Access Control

package authz

import future.keywords.if
import future.keywords.in

default allow := false
default reason := "Access denied: No matching policy rule"

# Rule 1: Admin Full Access
allow if {
    input.user.role == "admin"
}

reason := "Admin has full access to all resources" if {
    input.user.role == "admin"
}

# Rule 2: Manager - Office Hours Only (9 AM - 6 PM)
allow if {
    input.user.role == "manager"
    is_office_hours
    input.action in ["read", "write"]
    can_access_department
}

reason := "Manager access granted during office hours" if {
    input.user.role == "manager"
    is_office_hours
    input.action in ["read", "write"]
    can_access_department
}

reason := "Manager access denied: Outside office hours (9 AM - 6 PM)" if {
    input.user.role == "manager"
    not is_office_hours
}

# Rule 3: Employee - Read Only, Own Department
allow if {
    input.user.role == "employee"
    input.action == "read"
    same_department
}

reason := "Employee can read own department resources" if {
    input.user.role == "employee"
    input.action == "read"
    same_department
}

reason := "Employee access denied: Can only read, not write or delete" if {
    input.user.role == "employee"
    input.action in ["write", "delete"]
}

# Helper: Check office hours
is_office_hours if {
    input.environment.hour >= 9
    input.environment.hour < 18
}

# Helper: Same department
same_department if {
    input.user.department == input.resource.department
}

same_department if {
    input.resource.department == ""
}

# Helper: Can access department
can_access_department if {
    input.user.department == input.resource.department
}

can_access_department if {
    input.resource.department == ""
}
''',
        'is_active': True
    },
    {
        'name': 'rbac_policy',
        'description': 'Simple Role-Based Access Control policy. Assigns permissions based on user roles.',
        'version': '1.0.0',
        'policy_code': '''# Role-Based Access Control Policy
# ==================================

package rbac

import future.keywords.if
import future.keywords.in

role_permissions := {
    "admin": {
        "document": ["read", "write", "delete"],
        "report": ["read", "write", "delete"],
        "settings": ["read", "write", "delete"]
    },
    "manager": {
        "document": ["read", "write"],
        "report": ["read", "write"],
        "settings": ["read"]
    },
    "employee": {
        "document": ["read"],
        "report": ["read"],
        "settings": []
    }
}

default allow := false

allow if {
    permissions := role_permissions[input.user.role]
    allowed_actions := permissions[input.resource.type]
    input.action in allowed_actions
}

reason := sprintf("Role '%s' can '%s' resource type '%s'", [
    input.user.role, input.action, input.resource.type
]) if { allow }

reason := sprintf("Role '%s' cannot '%s' resource type '%s'", [
    input.user.role, input.action, input.resource.type
]) if { not allow }
''',
        'is_active': False
    },
    {
        'name': 'time_based_policy',
        'description': 'Time-based access control policy. Restricts access based on day and time.',
        'version': '1.0.0',
        'policy_code': '''# Time-Based Access Control Policy
# ==================================

package time_based

import future.keywords.if
import future.keywords.in

office_days := ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

default allow := false

is_weekday if {
    input.environment.day in office_days
}

is_office_hours if {
    input.environment.hour >= 9
    input.environment.hour < 18
}

# Admins: anytime
allow if { input.user.role == "admin" }

# Managers: weekdays, extended hours
allow if {
    input.user.role == "manager"
    is_weekday
    input.environment.hour >= 7
    input.environment.hour < 22
}

# Employees: weekdays, office hours only
allow if {
    input.user.role == "employee"
    is_weekday
    is_office_hours
}

reason := "Access granted based on time rules" if { allow }
reason := "Access denied: Outside allowed time window" if { not allow }
''',
        'is_active': False
    }
]

SAMPLE_USERS = [
    {
        'username': 'velsabrinaath',
        'email': 'vels@example.com',
        'password': 'employee123',
        'role': 'employee',
        'department': 'operations',
        'designation': 'software engineer'
    },
    {
        'username': 'velmurugan',
        'email': 'velm@example.com',
        'password': 'manager123',
        'role': 'manager',
        'department': 'engineering',
        'designation': 'Engineering Manager'
    },
    {
        'username': 'sriharan',
        'email': 'sri@example.com',
        'password': 'employee123',
        'role': 'employee',
        'department': 'engineering',
        'designation': 'Software Engineer'
    },
    {
        'username': 'vikkramvigneswarankj',
        'email': 'vikkram@example.com',
        'password': 'admin123',
        'role': 'admin',
        'department': 'management',
        'designation': 'Administrator'
    }
]


def init_database():
    """Initialize the database with sample data."""
    
    print("=" * 60)
    print("Policy-as-Code Platform - Database Initialization")
    print("=" * 60)
    print()
    
    # Create application context
    app = create_app('development')
    
    with app.app_context():
        # Create all tables
        print("📦 Creating database tables...")
        db.create_all()
        print("   ✅ Tables created successfully")
        print()
        
        # Create sample users
        print("👥 Creating sample users...")
        users_created = 0
        for user_data in SAMPLE_USERS:
            # Check if user already exists
            existing = User.query.filter_by(username=user_data['username']).first()
            if existing:
                print(f"   ⏭️  User '{user_data['username']}' already exists, skipping")
                continue
            
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role'],
                department=user_data['department'],
                designation=user_data['designation'],
                is_active=user_data.get('is_active', True)
            )
            user.set_password(user_data['password'])
            db.session.add(user)
            users_created += 1
            print(f"   ✅ Created user: {user_data['username']} ({user_data['role']})")
        
        db.session.commit()
        print(f"   📊 Total users created: {users_created}")
        print()
        
        # Create sample policies
        print("📜 Creating sample policies...")
        policies_created = 0
        for policy_data in SAMPLE_POLICIES:
            # Check if policy already exists
            existing = Policy.query.filter_by(name=policy_data['name']).first()
            if existing:
                print(f"   ⏭️  Policy '{policy_data['name']}' already exists, skipping")
                continue
            
            # Get admin user for created_by
            admin = User.query.filter_by(username='admin').first()
            
            policy = Policy(
                name=policy_data['name'],
                description=policy_data['description'],
                version=policy_data['version'],
                policy_code=policy_data['policy_code'],
                is_active=policy_data['is_active'],
                created_by=admin.id if admin else None
            )
            db.session.add(policy)
            policies_created += 1
            status = "Active" if policy_data['is_active'] else "Inactive"
            print(f"   ✅ Created policy: {policy_data['name']} [{status}]")
        
        db.session.commit()
        print(f"   📊 Total policies created: {policies_created}")
        print()
        
        # Summary
        print("=" * 60)
        print("✅ Database initialization complete!")
        print("=" * 60)
        print()
        print("📋 Summary:")
        print(f"   - Total users in database: {User.query.count()}")
        print(f"   - Total policies in database: {Policy.query.count()}")
        print(f"   - Active policies: {Policy.query.filter_by(is_active=True).count()}")
        print()
        print("🔑 Test Credentials:")
        print("   ┌────────────────────┬────────────────┬───────────────┐")
        print("   │ Username           │ Password       │ Role          │")
        print("   ├────────────────────┼────────────────┼───────────────┤")
        for user in SAMPLE_USERS:
            print(f"   │ {user['username']:<18} │ {user['password']:<14} │ {user['role']:<13} │")
        print("   └────────────────────┴────────────────┴───────────────┘")
        print()
        print("🚀 To start the application, run:")
        print("   python run.py")
        print()


if __name__ == '__main__':
    init_database()
