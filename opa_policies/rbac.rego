{
  "test_cases": [
    {
      "name": "Admin - Anytime Access",
      "input": {
        "user": {
          "role": "admin"
        },
        "environment": {
          "day": "Sunday",
          "hour": 2
        }
      },
      "expected": {
        "allow": true,
        "reason": "Access granted based on time rules"
      }
    },
    {
      "name": "Manager - Weekday Evening",
      "input": {
        "user": {
          "role": "manager"
        },
        "environment": {
          "day": "Tuesday",
          "hour": 21
        }
      },
      "expected": {
        "allow": true,
        "reason": "Access granted based on time rules"
      }
    },
    {
      "name": "Employee - Late Night (Denied)",
      "input": {
        "user": {
          "role": "employee"
        },
        "environment": {
          "day": "Monday",
          "hour": 20
        }
      },
      "expected": {
        "allow": false,
        "reason": "Access denied: Outside allowed time window"
      }
    }
  ]
}