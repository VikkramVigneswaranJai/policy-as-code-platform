## Policy-as-Code Platform

A comprehensive Flask-based authorization system using Open Policy Agent (OPA) for implementing Policy-as-Code principles with Attribute-Based Access Control (ABAC).

### 🎯 Project Overview

This platform demonstrates modern authorization patterns using declarative policies written in Rego. It provides a complete web application with user management, policy evaluation, and comprehensive audit logging.

## Key Features

 • 🔐 Authentication & Authorization**: JWT-based authentication with OPA policy evaluation
 • 👥 User Management**: Complete user registration, login, and profile management
 • 📜 Policy Management**: Create, update, and manage Rego policies through web interface
 • 🔍 Audit Logging**: Comprehensive logging of all authorization decisions
 • ⏰ Time-Based Access Control**: Policies that consider time of day and day of week
 • 🏢 Department-Based Access**: ABAC policies based on user and resource departments
 • 🎨 Modern UI**: Beautiful, responsive interface built with Tailwind CSS
 • 🧪 Comprehensive Testing**: Full test suite covering all endpoints and edge cases

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [API Documentation](#api-documentation)
- [Policy Examples](#policy-examples)
- [Testing](#testing)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- OPA (Open Policy Agent) - Optional but recommended

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd PolicyAsCodePlatform
```

### Step 2: Create Virtual Environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Install OPA (Optional)

#### Windows

1. Download OPA from: https://www.openpolicyagent.org/docs/latest/#running-opa
2. Or use direct link: https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe
3. Rename to `opa.exe` and add to PATH

#### Linux

```bash
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod +x opa
sudo mv opa /usr/local/bin/
```

#### Mac

```bash
brew install opa
```

### Step 5: Initialize Database

```bash
python init_db.py
```

This creates the SQLite database and populates it with sample users and policies.

## ⚡ Quick Start

### Option 1: Integrated Startup (Recommended)

Starts both OPA server and Flask application together:

```bash
python start_app.py
```

### Option 2: Manual Startup

**Terminal 1 - Start OPA Server:**
```bash
python start_opa.py
# Or manually:
opa run --server --addr localhost:8181 opa_policies/
```

**Terminal 2 - Start Flask Application:**
```bash
python run.py
```

### Access the Application

- **Web Interface**: http://localhost:5000
- **Dashboard**: http://localhost:5000/dashboard
- **Login**: http://localhost:5000/login
- **Register**: http://localhost:5000/register
- **API Docs**: http://localhost:5000/api-docs
- **OPA Server**: http://localhost:8181 (if running)

### Default Test Credentials

| Username | Password | Role | Department |
|----------|----------|------|------------|
| admin | admin123 | admin | management |
| manager | manager123 | manager | engineering |
| employee | employee123 | employee | engineering |
| hr_manager | hr123 | manager | hr |
| finance_employee | finance123 | employee | finance |

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Web Browser (Client)                     │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTP/HTTPS
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   Flask Application                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Auth Routes  │  │Policy Routes │  │ Audit Routes │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────────────────────────────────────────────┐     │
│  │            OPA Client Module                      │     │
│  └──────────────────────────────────────────────────────┘     │
└──────────────┬────────────────────────┬────────────────────┘
                │                         │
                ▼                         ▼
    ┌───────────────────┐    ┌───────────────────────┐
    │  SQLite Database  │    │   OPA Server          │
    │  - Users          │    │   - Policy Engine     │
    │  - Policies       │    │   - Rego Policies     │
    │  - Audit Logs     │    │   - REST API          │
    └───────────────────┘    └───────────────────────┘
```

### Technology Stack

- **Backend**: Flask 2.3.3
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: JWT (Flask-JWT-Extended)
- **Policy Engine**: Open Policy Agent (OPA)
- **Policy Language**: Rego
- **Frontend**: HTML5, Tailwind CSS, Vanilla JavaScript
- **Testing**: pytest

### Directory Structure

```
PolicyAsCodePlatform/
├── app/
│   ├── __init__.py              # Application factory
│   ├── models.py                # Database models
│   ├── opa_client.py            # OPA integration
│   ├── routes.py                # Main routes
│   ├── auth/
│   │   └── routes.py            # Authentication endpoints
│   ├── policy/
│   │   └── routes.py            # Policy management endpoints
│   ├── resources/
│   │   └── routes.py            # Resource access endpoints
│   ├── audit/
│   │   └── routes.py            # Audit log endpoints
│   └── templates/               # HTML templates
│       ├── base.html
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html
│       └── ...
├── opa_policies/
│   ├── authz.rego               # Main authorization policy
│   ├── rbac.rego                # Role-based access control
│   ├── time_based.rego          # Time-based policies
│   └── department.rego          # Department-based policies
├── config.py                    # Configuration settings
├── run.py                       # Application entry point
├── start_app.py                 # Integrated startup script
├── start_opa.py                 # OPA startup script
├── init_db.py                   # Database initialization
├── test_app.py                  # Comprehensive test suite
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## 📚 API Documentation

### Authentication Endpoints

#### POST /auth/register
Register a new user account.

**Request Body:**
```json
{
  "username": "string",
  "email": "string",
  "password": "string",
  "role": "admin|manager|employee",
  "department": "string",
  "designation": "string (optional)"
}
```

**Response (201):**
```json
{
  "status": "success",
  "message": "User registered successfully",
  "data": {
    "user": { ... }
  }
}
```

#### POST /auth/login
Authenticate and receive JWT token.

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "token_type": "Bearer",
    "user": { ... }
  }
}
```

#### GET /auth/profile
Get current user profile (requires authentication).

**Headers:**
```
Authorization: Bearer <token>
```

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin",
      "department": "management"
    }
  }
}
```

### Policy Endpoints

#### POST /policy/evaluate
Evaluate a policy decision.

**Headers:**
```
Authorization: Bearer <token>
```

**Request Body:**
```json
{
  "action": "read|write|delete",
  "resource": {
    "type": "document|report|settings",
    "department": "string",
    "id": "string (optional)"
  },
  "environment": {
    "hour": 14,
    "day": "Monday"
  }
}
```

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "allow": true,
    "reason": "Admin has full access to all resources"
  }
}
```

### Audit Endpoints

#### GET /audit/logs
Retrieve audit logs (admin only).

**Query Parameters:**
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20)
- `decision`: Filter by decision (allow/deny)
- `action`: Filter by action (read/write/delete)

## 🔒 Policy Examples

### Example 1: Admin Full Access

```rego
allow if {
    input.user.role == "admin"
}
```

### Example 2: Manager Office Hours

```rego
allow if {
    input.user.role == "manager"
    input.environment.hour >= 9
    input.environment.hour < 18
    input.action in ["read", "write"]
}
```

### Example 3: Employee Department Access

```rego
allow if {
    input.user.role == "employee"
    input.action == "read"
    input.user.department == input.resource.department
}
```

## 🧪 Testing

### Run All Tests

```bash
python -m pytest test_app.py -v
```

### Run Specific Test Class

```bash
python -m pytest test_app.py::TestAuthEndpoints -v
```

### Test Coverage

The test suite covers:
- ✅ User registration (success, duplicates, validation)
- ✅ User login (success, invalid credentials)
- ✅ JWT token handling
- ✅ Policy evaluation (all roles and scenarios)
- ✅ Time-based access control
- ✅ Department-based access control
- ✅ Audit logging
- ✅ Edge cases (SQL injection, XSS, malformed input)
- ✅ Error handling

## 🌐 Deployment

### Production Considerations

1. **Environment Variables**: Set production secrets
   ```bash
   export SECRET_KEY="your-secret-key"
   export JWT_SECRET_KEY="your-jwt-secret"
   export FLASK_ENV="production"
   ```

2. **Database**: Use PostgreSQL or MySQL instead of SQLite
   ```python
   SQLALCHEMY_DATABASE_URI = "postgresql://user:pass@localhost/dbname"
   ```

3. **OPA Server**: Deploy OPA as a separate service
   ```bash
   opa run --server --addr 0.0.0.0:8181 /path/to/policies
   ```

4. **WSGI Server**: Use Gunicorn or uWSGI
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 run:app
   ```

## 🔧 Troubleshooting

### OPA Server Not Starting

**Problem**: OPA executable not found

**Solution**: 
- Ensure OPA is installed and in PATH
- Or use local fallback mode (application works without OPA)

### Database Errors

**Problem**: Database locked or permission errors

**Solution**:
```bash
# Delete and recreate database
rm pac_platform.db
python init_db.py
```

### Port Already in Use

**Problem**: Port 5000 or 8181 already in use

**Solution**:
```bash
# Change Flask port
export FLASK_PORT=8000
python run.py

# Or kill existing process
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:5000 | xargs kill -9
```

### Login Not Working

**Problem**: Token not being stored

**Solution**:
- Check browser console for errors
- Ensure JavaScript is enabled
- Clear browser localStorage
- Try incognito/private mode

## 📝 Configuration

### Environment Variables

- `FLASK_ENV`: Environment (development/production/testing)
- `FLASK_DEBUG`: Enable debug mode (True/False)
- `FLASK_HOST`: Host address (default: 0.0.0.0)
- `FLASK_PORT`: Port number (default: 5000)
- `SECRET_KEY`: Flask secret key
- `JWT_SECRET_KEY`: JWT signing key
- `OPA_SERVER_URL`: OPA server URL (default: http://localhost:8181)
- `DATABASE_URL`: Database connection string

### Configuration Files

- `config.py`: Main configuration
- `.env`: Environment variables (create from `.env.example`)

## 🤝 Contributing

This is an academic project. For improvements:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is created for academic purposes.

## 👥 Authors

- Academic Project - Policy-as-Code Platform
- Vikkram Vigneswaran KJ
- Velmurugan A
- Velsabarinaath B
- Sri haran R

## 🙏 Acknowledgments

- Open Policy Agent (OPA) team
- Flask framework contributors
- Tailwind CSS team

## 📞 Support

For issues or questions:
- Check the troubleshooting section
- Review the API documentation
- Run the test suite to verify setup
## Mail To-
- Vikkram Vigneswaran - vvigneswarankj@gmail.com

---

**Built with ❤️ using Flask, OPA, and modern web technologies**
