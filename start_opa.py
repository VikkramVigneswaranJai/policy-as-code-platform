"""
OPA Server Startup Script
==========================
This script starts the Open Policy Agent (OPA) server with the policies from opa_policies directory.

Usage:
    python start_opa.py

The OPA server will start on http://localhost:8181
"""

import subprocess
import sys
import os
import time
import requests
from pathlib import Path


def get_opa_executable():
    """Return the OPA executable path.

    On Windows, prefer a local opa.exe in the project root if available.
    Otherwise, use the system PATH executable name.
    """
    if sys.platform == 'win32':
        local_opa = Path(__file__).parent / 'opa.exe'
        if local_opa.exists():
            return str(local_opa)
    return 'opa'


def check_opa_installed():
    """Check if OPA is installed and available in PATH or locally."""
    opa_executable = get_opa_executable()
    try:
        result = subprocess.run([opa_executable, 'version'],
                                capture_output=True,
                                text=True,
                                timeout=5)
        if result.returncode == 0:
            print(f"✅ OPA is installed: {result.stdout.strip()}")
            return True
        return False
    except FileNotFoundError:
        return False
    except Exception as e:
        print(f"Error checking OPA: {e}")
        return False

def download_opa_windows():
    """Provide instructions to download OPA for Windows."""
    print("\n" + "="*60)
    print("OPA is not installed on your system.")
    print("="*60)
    print("\nTo install OPA on Windows:")
    print("\n1. Download OPA from:")
    print("   https://www.openpolicyagent.org/docs/latest/#running-opa")
    print("\n2. Or use this direct link:")
    print("   https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe")
    print("\n3. Rename the downloaded file to 'opa.exe'")
    print("\n4. Add it to your PATH or place it in this project directory")
    print("\nAlternatively, you can use the local fallback mode.")
    print("The application will work without OPA but with limited policy features.")
    print("="*60 + "\n")

def start_opa_server(policy_dir):
    """Start OPA server with policies from the specified directory."""
    
    # Check if OPA is installed
    if not check_opa_installed():
        download_opa_windows()
        print("\n⚠️  Starting application in LOCAL FALLBACK MODE")
        print("   OPA policies will be evaluated using Python fallback logic.\n")
        return None
    
    # Check if policy directory exists
    if not os.path.exists(policy_dir):
        print(f"❌ Policy directory not found: {policy_dir}")
        return None
    
    print(f"\n🚀 Starting OPA server...")
    print(f"   Policy directory: {policy_dir}")
    print(f"   Server URL: http://localhost:8181\n")
    
    try:
        opa_executable = get_opa_executable()
        if opa_executable != 'opa':
            print(f"Using local OPA executable: {opa_executable}")

        # Start OPA server as a subprocess
        # --server: Run in server mode
        # --addr: Listen address
        # policy_dir: Directory containing .rego files
        process = subprocess.Popen(
            [opa_executable, 'run', '--server', '--addr', 'localhost:8181', policy_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == 'win32' else 0
        )
        
        # Wait for server to start and check health
        for attempt in range(10):
            try:
                response = requests.get('http://localhost:8181/health', timeout=2)
                if response.status_code == 200:
                    print("✅ OPA server started successfully!")
                    print("   Health check: PASSED")
                    return process
                print(f"⚠️  OPA server responded with status {response.status_code}")
                return process
            except requests.exceptions.ConnectionError:
                print(f"⏳ Waiting for OPA to initialize... (attempt {attempt + 1}/10)")
                time.sleep(1)
        print("⚠️  OPA server started but health check failed after several attempts.")
        print("   The server may still be initializing or failed to bind.")
        return process
            
    except FileNotFoundError:
        print("❌ OPA executable not found in PATH")
        download_opa_windows()
        return None
    except Exception as e:
        print(f"❌ Error starting OPA server: {e}")
        return None

def main():
    """Main function to start OPA server."""
    
    # Get the policy directory path
    base_dir = Path(__file__).parent
    policy_dir = base_dir / 'opa_policies'
    
    print("\n" + "="*60)
    print("  OPA Server Startup")
    print("="*60)
    
    # Start OPA server
    process = start_opa_server(str(policy_dir))
    
    if process:
        print("\n📋 OPA Server Information:")
        print(f"   - Process ID: {process.pid}")
        print(f"   - API Endpoint: http://localhost:8181/v1/data")
        print(f"   - Health Check: http://localhost:8181/health")
        print("\n💡 To stop the OPA server:")
        print("   - Close the OPA console window, or")
        print("   - Press Ctrl+C in this terminal")
        print("\n" + "="*60 + "\n")
        
        try:
            # Keep the script running
            print("OPA server is running. Press Ctrl+C to stop...")
            process.wait()
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping OPA server...")
            process.terminate()
            process.wait()
            print("✅ OPA server stopped.\n")
    else:
        print("\n⚠️  OPA server could not be started.")
        print("   The application will run in LOCAL FALLBACK MODE.\n")

if __name__ == '__main__':
    main()
