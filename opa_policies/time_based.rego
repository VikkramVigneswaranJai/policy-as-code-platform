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

# =============================================================================
# ACCESS RULES
# =============================================================================

# Admins can access anytime
allow if {
    input.user.role == "admin"
}

# Managers: weekdays during extended hours
allow if {
    input.user.role == "manager"
    is_weekday
    is_extended_hours
}

# Employees: weekdays during office hours only
allow if {
    input.user.role == "employee"
    is_weekday
    is_office_hours
}

# Generate reason
reason := "Admin access: No time restrictions" if {
    input.user.role == "admin"
}

reason := "Manager access granted during extended hours (7 AM - 10 PM on weekdays)" if {
    input.user.role == "manager"
    is_weekday
    is_extended_hours
}

reason := "Manager access denied: Outside extended hours or weekend" if {
    input.user.role == "manager"
    not allow
}

reason := "Employee access granted during office hours (9 AM - 6 PM on weekdays)" if {
    input.user.role == "employee"
    is_weekday
    is_office_hours
}

reason := "Employee access denied: Outside office hours or weekend" if {
    input.user.role == "employee"
    not allow
}
