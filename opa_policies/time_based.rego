# Time-Based Access Control Policy
# ==================================
# This policy demonstrates time-based access restrictions.
# Access can be restricted based on:
# - Time of day
# - Day of week
# - Specific time windows

package time_based

import future.keywords.if
import future.keywords.in

# Default deny
default allow := false

# Office hours: Monday to Friday, 9 AM to 6 PM
office_days := ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]

# Check if it's a weekday
is_weekday if {
    input.environment.day in office_days
}

# Check if it's during office hours (9 AM to 6 PM)
is_office_hours if {
    input.environment.hour >= 9
    input.environment.hour < 18
}

# Check if it's during extended hours (7 AM to 10 PM)
is_extended_hours if {
    input.environment.hour >= 7
    input.environment.hour < 22
}

# Check if it's before 6 PM
is_before_six if {
    input.environment.hour < 18
}

# Check if it's a weekend day
is_weekend if {
    not is_weekday
}

# =============================================================================
# ACCESS RULES
# =============================================================================

# Admins can access anytime
allow if {
    input.user.role == "admin"
}

# Managers can read anytime, but can write only on weekdays before 6 PM
allow if {
    input.user.role == "manager"
    input.action == "read"
}

allow if {
    input.user.role == "manager"
    input.action == "write"
    is_weekday
    is_before_six
}

# Managers cannot delete at any time

# Employees can only read, at any time
allow if {
    input.user.role == "employee"
    input.action == "read"
}

# Generate reason
reason := "Admin access: No time restrictions" if {
    input.user.role == "admin"
}

reason := "Manager access granted: read anytime, write only weekdays before 6 PM" if {
    input.user.role == "manager"
    input.action == "read"
}

reason := "Manager access granted: write allowed weekdays before 6 PM" if {
    input.user.role == "manager"
    input.action == "write"
    is_weekday
    is_before_six
}

reason := "Manager access denied: no write on weekends or after 6 PM, delete never allowed" if {
    input.user.role == "manager"
    input.action in ["write", "delete"]
    not (is_weekday and is_before_six)
}

reason := "Employee access granted: read only at any time" if {
    input.user.role == "employee"
    input.action == "read"
}

reason := "Employee access denied: employees cannot write or delete" if {
    input.user.role == "employee"
    input.action in ["write", "delete"]
}
