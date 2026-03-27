"""
Policy-as-Code Platform - Application Entry Point
==================================================
This is the main entry point for running the Flask application.

Usage:
    python run.py

The application will start on http://localhost:5000 by default.
"""

import os
from app import create_app

# Create the Flask application instance
# Use 'development' config by default, can be overridden via environment variable
config_name = os.environ.get('FLASK_CONFIG', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    # Get configuration from environment or use defaults
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║           Policy-as-Code Platform                             ║
    ║           ========================                            ║
    ║                                                               ║
    ║   A Flask-based authorization system using                    ║
    ║   Open Policy Agent (OPA) for Policy-as-Code                  ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    print(f"  🚀 Starting server on http://{host}:{port}")
    print(f"  📁 Configuration: {config_name}")
    print(f"  🔧 Debug mode: {debug}")
    print("")
    print("  📚 Quick Links:")
    print(f"     - Dashboard:    http://localhost:{port}/dashboard")
    print(f"     - API Docs:     http://localhost:{port}/api-docs")
    print(f"     - Login:        http://localhost:{port}/login")
    print("")
    print("  🔑 Test Credentials:")
    print("     - Admin:    admin / admin123")
    print("     - Manager:  manager / manager123")
    print("     - Employee: employee / employee123")
    print("")
    print("  💡 To start OPA server (optional):")
    print("     opa run --server opa_policies/")
    print("")
    print("  Press Ctrl+C to stop the server")
    print("  " + "=" * 60)
    print("")
    
    # Run the Flask development server
    app.run(host=host, port=port, debug=debug)
