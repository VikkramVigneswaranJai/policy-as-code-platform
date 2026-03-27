# Department-Based Access Control Policy
# ========================================
# This policy enforces department-level data isolation.
# Users can only access resources belonging to their department.

package department

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Department hierarchy - some departments can access others
department_access := {
    "engineering": ["engineering"],
    "hr": ["hr", "general"],
    "finance": ["finance", "general"],
    "management": ["engineering", "hr", "finance", "general"],
    "general": ["general"]
}

# Check if user's department can access resource's department
can_access_department if {
    user_dept := input.user.department
    resource_dept := input.resource.department
    
    # Get accessible departments for user's department
    accessible := department_access[user_dept]
    
    # Check if resource department is accessible
    resource_dept in accessible
}

# Also allow if resource has no specific department
can_access_department if {
    input.resource.department == ""
}

# =============================================================================
# ACCESS RULES
# =============================================================================

# Allow if user can access the department
allow if {
    can_access_department
}

# Generate reason
reason := sprintf("User from '%s' department can access '%s' department resources", [
    input.user.department,
    input.resource.department
]) if {
    can_access_department
}

reason := sprintf("User from '%s' department cannot access '%s' department resources", [
    input.user.department,
    input.resource.department
]) if {
    not can_access_department
}
