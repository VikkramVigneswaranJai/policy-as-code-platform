# Role-Based Access Control (RBAC) Policy
# =========================================
# This policy demonstrates a simpler RBAC model as an alternative
# to the full ABAC policy in authz.rego.
#
# RBAC assigns permissions to roles, and users inherit permissions
# from their assigned roles.

package rbac

import future.keywords.if
import future.keywords.in

# Role hierarchy and permissions
# Each role has a set of allowed actions on resource types

role_permissions := {
    "admin": {
        "document": ["read", "write", "delete"],
        "report": ["read", "write", "delete"],
        "settings": ["read", "write", "delete"],
        "user": ["read", "write", "delete"]
    },
    "manager": {
        "document": ["read", "write"],
        "report": ["read", "write"],
        "settings": ["read"],
        "user": ["read"]
    },
    "employee": {
        "document": ["read"],
        "report": ["read"],
        "settings": [],
        "user": []
    }
}

# Default deny
default allow := false

# Check if the user's role has permission for the action on the resource type
allow if {
    role := input.user.role
    resource_type := input.resource.type
    action := input.action
    
    # Get permissions for the role
    permissions := role_permissions[role]
    
    # Get allowed actions for the resource type
    allowed_actions := permissions[resource_type]
    
    # Check if action is allowed
    action in allowed_actions
}

# Generate reason for the decision
reason := sprintf("Role '%s' is allowed to '%s' resource type '%s'", [
    input.user.role,
    input.action,
    input.resource.type
]) if {
    allow
}

reason := sprintf("Role '%s' is NOT allowed to '%s' resource type '%s'", [
    input.user.role,
    input.action,
    input.resource.type
]) if {
    not allow
}
