# Policy-as-Code Platform - Main Authorization Policy
# =====================================================
# This Rego policy implements Attribute-Based Access Control (ABAC)
# for the Policy-as-Code Platform.
#
# Policy Package: authz
#
# This policy evaluates authorization requests based on:
# - User attributes (role, department, designation)
# - Resource attributes (type, department, id)
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

default reason := "Access denied: No matching policy rule"

# =============================================================================
# ROLE-LEVEL BASED ACCESS
# =============================================================================
# - admin: full access to everything
# - manager: read own department anytime; write own department only during office hours
# - employee: view-only (read) and only for own department

allow if {
    is_admin
}

reason := "Admin has full access to all resources" if {
    is_admin
}

allow if {
    is_manager
    input.action == "read"
    can_access_department
    not is_settings_resource
}

allow if {
    is_manager
    input.action == "write"
    is_office_hours
    can_access_department
}

reason := "Manager access granted: read department resources anytime" if {
    is_manager
    input.action == "read"
    can_access_department
}

reason := "Manager access granted: write allowed during office hours for department resources" if {
    is_manager
    input.action == "write"
    is_office_hours
    can_access_department
}

reason := "Manager access denied: write only allowed during office hours, delete not permitted" if {
    is_manager
    input.action in ["write", "delete"]
    not input.action == "write"
}

reason := "Manager access denied: write only allowed during office hours, delete not permitted" if {
    is_manager
    input.action == "write"
    not is_office_hours
}

reason := "Manager access denied: write only allowed during office hours, delete not permitted" if {
    is_manager
    input.action == "write"
    not can_access_department
}

reason := "Manager access denied: Cannot access other department resources" if {
    is_manager
    input.action in ["read", "write"]
    not can_access_department
}

allow if {
    is_employee
    input.action == "read"
    same_department
    not is_sensitive_report
    not is_settings_resource
}

reason := "Employee can read own department resources anytime" if {
    is_employee
    input.action == "read"
    same_department
    not is_sensitive_report
    not is_settings_resource
}

reason := "Employee access denied: cannot write or delete resources" if {
    is_employee
    input.action in ["write", "delete"]
}

reason := "Employee access denied: Cannot access other department data" if {
    is_employee
    input.action == "read"
    not same_department
}

reason := "Employee access denied: Reports are reserved for managers and admins" if {
    is_employee
    is_sensitive_report
}

# =============================================================================
# RESOURCE AND ENVIRONMENT HELPERS
# =============================================================================

is_admin if {
    input.user.role == "admin"
}

is_manager if {
    input.user.role == "manager"
}

is_employee if {
    input.user.role == "employee"
}

is_office_hours if {
    input.environment.hour >= 9
    input.environment.hour < 18
}

is_delete_action if {
    input.action == "delete"
}

same_department if {
    input.user.department == input.resource.department
}

same_department if {
    input.resource.department == ""
}

can_access_department if {
    same_department
}

is_sensitive_report if {
    input.resource.type == "report"
}

is_settings_resource if {
    input.resource.type == "settings"
}

# =============================================================================
# SPECIAL RESOURCE RULES
# =============================================================================

reason := "Settings access requires admin role" if {
    is_settings_resource
    not is_admin
}

allow if {
    is_sensitive_report
    is_manager
    input.action == "read"
}

allow if {
    is_sensitive_report
    is_admin
}

reason := "Report access granted for managers and admins" if {
    is_sensitive_report
    input.action == "read"
    input.user.role in ["admin", "manager"]
}
