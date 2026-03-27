# Policy-as-Code Platform - Main Authorization Policy
# =====================================================
# This Rego policy implements Attribute-Based Access Control (ABAC)
# for the Policy-as-Code Platform.
#
# Policy Package: authz
# 
# This policy evaluates authorization requests based on:
# - User attributes (role, department, designation)
# - Resource attributes (type, department, sensitivity)
# - Action (read, write, delete)
# - Environment (time, day, IP address)
#
# The policy returns an object with:
# - allow: boolean indicating if access is permitted
# - reason: string explaining the decision

package authz

import future.keywords.if
import future.keywords.in

# Default deny - all access is denied unless explicitly allowed
default allow := false

# Default reason for denial
default reason := "Access denied: No matching policy rule"

# =============================================================================
# RULE 1: Admin Full Access
# =============================================================================
# Administrators have unrestricted access to all resources and actions.
# This is the highest privilege level in the system.

allow if {
    input.user.role == "admin"
}

reason := "Admin has full access to all resources" if {
    input.user.role == "admin"
}

# =============================================================================
# RULE 2: Manager Access - Office Hours Only (9 AM - 6 PM)
# =============================================================================
# Managers can access resources during business hours.
# They can read and write resources in their own department.
# They cannot delete resources.

allow if {
    input.user.role == "manager"
    is_office_hours
    input.action in ["read", "write"]
    can_access_department
}

reason := "Manager access granted during office hours for department resources" if {
    input.user.role == "manager"
    is_office_hours
    input.action in ["read", "write"]
    can_access_department
}

reason := "Manager access denied: Outside office hours (9 AM - 6 PM)" if {
    input.user.role == "manager"
    not is_office_hours
}

reason := "Manager access denied: Delete action not permitted" if {
    input.user.role == "manager"
    input.action == "delete"
}

reason := "Manager access denied: Cannot access other department resources" if {
    input.user.role == "manager"
    is_office_hours
    input.action in ["read", "write"]
    not can_access_department
}

# =============================================================================
# RULE 3: Employee Access - Read Only, Own Department
# =============================================================================
# Employees can only read resources from their own department.
# They cannot write or delete any resources.

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

reason := "Employee access denied: Cannot access other department data" if {
    input.user.role == "employee"
    input.action == "read"
    not same_department
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# Check if current time is within office hours (9 AM to 6 PM)
is_office_hours if {
    input.environment.hour >= 9
    input.environment.hour < 18
}

# Check if user and resource are in the same department
same_department if {
    input.user.department == input.resource.department
}

# Also allow if resource has no specific department (general access)
same_department if {
    input.resource.department == ""
}

# Check if user can access the resource's department
# Managers can access their own department or general resources
can_access_department if {
    input.user.department == input.resource.department
}

can_access_department if {
    input.resource.department == ""
}

# =============================================================================
# SPECIAL RESOURCE RULES
# =============================================================================

# Settings can only be accessed by admins (already covered by admin rule)
reason := "Settings access requires admin role" if {
    input.resource.type == "settings"
    input.user.role != "admin"
}

# Sensitive reports require manager or admin role
allow if {
    input.resource.type == "report"
    input.user.role in ["admin", "manager"]
    input.action == "read"
}

reason := "Report access granted for managers and admins" if {
    input.resource.type == "report"
    input.user.role in ["admin", "manager"]
    input.action == "read"
}
