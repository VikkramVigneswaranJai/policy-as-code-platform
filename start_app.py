"""
Integrated Application Startup Script
======================================
This script starts both the OPA server and Flask application together.

Usage:
    python start_app.py

This will:
1. Check if OPA is installed
2. Start OPA server with policies (if available)
3. Start Flask application
4. Handle graceful shutdown of both services
"""

import subprocess
import sys
import os
import time
import requests
import signal
from pathlib import Path
from threading import Thread

# Global process references
opa_process = None
flask_process = None

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print("\n\n🛑 Shutting down services...")
    
    if flask_process:
        print("   Stopping Flask application...")
        flask_process.terminate()
        flask_process.wait()
    
    if opa_process:
        print("   Stopping OPA server...")
        opa_process.terminate()
        opa_process.wait()
    
    print("✅ All services stopped.\n")
    sys.exit(0)

def check_opa_installed():
    """Check if OPA is installed."""
    try:
        result = subprocess.run(['opa', 'version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        return result.returncode == 0
    except:
        return False

def start_opa_server(policy_dir):
    """Start OPA server in background."""
    global opa_process
    
    if not check_opa_installed():
        print("⚠️  OPA not installed - running in FALLBACK MODE")
        return None
    
    if not os.path.exists(policy_dir):
        print(f"⚠️  Policy directory not found: {policy_dir}")
        return None
    
    print("🚀 Starting OPA server...")
    
    try:
        opa_process = subprocess.Popen(
            ['opa', 'run', '--server', '--addr', 'localhost:8181', policy_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0
        )
        
        # Wait for OPA to start
        time.sleep(2)
        
        # Verify OPA is running
        try:
            response = requests.get('http://localhost:8181/health', timeout=2)
            if response.status_code == 200:
                print("✅ OPA server started on http://localhost:8181")
                return opa_process
        except:
            pass
        
        print("⚠️  OPA server started but health check failed")
        return opa_process
        
    except Exception as e:
        print(f"❌ Error starting OPA: {e}")
        return None

def start_flask_app():
    """Start Flask application."""
    global flask_process
    
    print("🚀 Starting Flask application...")
    
    try:
        flask_process = subprocess.Popen(
            [sys.executable, 'run.py'],
            stdout=sys.stdout,
            stderr=sys.stderr
        )
        
        print("✅ Flask application started")
        return flask_process
        
    except Exception as e:
        print(f"❌ Error starting Flask: {e}")
        return None

def main():
    """Main startup function."""
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    print("\n" + "="*70)
    print("  Policy-as-Code Platform - Integrated Startup")
    print("="*70)
    print()
    
    # Get policy directory
    base_dir = Path(__file__).parent
    policy_dir = base_dir / 'opa_policies'
    
    # Start OPA server
    opa_proc = start_opa_server(str(policy_dir))
    
    print()
    
    # Start Flask application
    flask_proc = start_flask_app()
    
    if not flask_proc:
        print("\n❌ Failed to start Flask application")
        if opa_proc:
            opa_proc.terminate()
        sys.exit(1)
    
    print()
    print("="*70)
    print("  🎉 All services started successfully!")
    print("="*70)
    print()
    print("📋 Service Status:")
    if opa_proc:
        print(f"   ✅ OPA Server:        http://localhost:8181")
    else:
        print(f"   ⚠️  OPA Server:        FALLBACK MODE (local evaluation)")
    print(f"   ✅ Flask Application: http://localhost:5000")
    print()
    print("🔗 Quick Links:")
    print("   - Dashboard:    http://localhost:5000/dashboard")
    print("   - Login:        http://localhost:5000/login")
    print("   - Register:     http://localhost:5000/register")
    print("   - API Docs:     http://localhost:5000/api-docs")
    print()
    print("💡 Press Ctrl+C to stop all services")
    print("="*70)
    print()
    
    try:
        # Wait for Flask process
        flask_proc.wait()
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == '__main__':
    main()
