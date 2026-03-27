"""
OPA (Open Policy Agent) Client Module
======================================
This module handles communication with the OPA policy engine.
It provides functions to evaluate authorization requests against Rego policies.

Key Features:
- HTTP client for OPA REST API
- Local policy evaluation fallback (when OPA server is not available)
- Policy file management
- Authorization decision caching (optional)
"""

import os
import json
import requests
from datetime import datetime
from flask import current_app
from functools import wraps


class OPAClient:
    """
    OPA Client for Policy Evaluation
    
    This client can work in two modes:
    1. Remote Mode: Connects to a running OPA server via HTTP
    2. Local Mode: Evaluates policies locally using policy files
    
    For this academic project, we primarily use Remote Mode with OPA server,
    but provide Local Mode as a fallback for testing.
    """
    
    def __init__(self, opa_url=None):
        """
        Initialize OPA Client.
        
        Args:
            opa_url (str): OPA server URL (e.g., http://localhost:8181)
        """
        self.opa_url = opa_url or 'http://localhost:8181'
        self.policy_cache = {}
    
    def evaluate_policy(self, input_data, policy_path='authz/allow'):
        """
        Evaluate a policy against the given input data.
        
        This is the core function that sends authorization requests to OPA.
        
        Args:
            input_data (dict): Input data for policy evaluation containing:
                - user: User attributes (role, department, etc.)
                - action: Requested action (read, write, delete)
                - resource: Resource being accessed
                - environment: Environmental context (time, IP)
            policy_path (str): OPA policy path to evaluate
        
        Returns:
            dict: Evaluation result with 'allow' boolean and optional 'reason'
        
        Example input_data:
            {
                "user": {"role": "manager", "department": "engineering"},
                "action": "read",
                "resource": {"type": "document", "department": "engineering"},
                "environment": {"time": "14:00", "ip": "192.168.1.1"}
            }
        """
        try:
            # Construct OPA query URL
            # OPA v1 Data API: POST /v1/data/{policy_path}
            url = f"{self.opa_url}/v1/data/{policy_path}"
            
            # Prepare request payload
            payload = {"input": input_data}
            
            # Send request to OPA
            response = requests.post(
                url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=5  # 5 second timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                # OPA returns {"result": <value>} for successful queries
                # If policy returns a boolean, result will be True/False
                # If policy returns an object, we extract the relevant fields
                
                if 'result' in result:
                    policy_result = result['result']
                    
                    # Handle different return types
                    if isinstance(policy_result, bool):
                        return {
                            'allow': policy_result,
                            'reason': 'Policy evaluation completed'
                        }
                    elif isinstance(policy_result, dict):
                        return {
                            'allow': policy_result.get('allow', False),
                            'reason': policy_result.get('reason', 'No reason provided')
                        }
                    else:
                        return {
                            'allow': False,
                            'reason': 'Unexpected policy result format'
                        }
                else:
                    # No result means policy not found or undefined
                    return {
                        'allow': False,
                        'reason': 'Policy not found or undefined'
                    }
            else:
                return {
                    'allow': False,
                    'reason': f'OPA server error: {response.status_code}'
                }
                
        except requests.exceptions.ConnectionError:
            # OPA server not available - use local fallback
            return self._local_fallback_evaluation(input_data)
        except requests.exceptions.Timeout:
            return {
                'allow': False,
                'reason': 'OPA server timeout'
            }
        except Exception as e:
            return {
                'allow': False,
                'reason': f'Policy evaluation error: {str(e)}'
            }
    
    def _local_fallback_evaluation(self, input_data):
        """
        Local fallback policy evaluation.
        Used when OPA server is not available.
        
        This implements a simple Python-based policy evaluation
        that mirrors the Rego policies for testing purposes.
        
        WARNING: In production, always use OPA server for policy evaluation.
        This fallback is for development/testing only.
        """
        user = input_data.get('user', {})
        action = input_data.get('action', '')
        resource = input_data.get('resource', {})
        environment = input_data.get('environment', {})
        
        role = user.get('role', '')
        user_dept = user.get('department', '')
        resource_type = resource.get('type', '')
        resource_dept = resource.get('department', '')
        
        # Rule 1: Admin can access everything
        if role == 'admin':
            return {
                'allow': True,
                'reason': 'Admin has full access to all resources'
            }
        
        # Rule 2: Manager can only access during office hours (9 AM - 6 PM)
        if role == 'manager':
            current_hour = datetime.now().hour
            if environment.get('hour'):
                current_hour = int(environment.get('hour'))
            
            if 9 <= current_hour < 18:
                # Manager can access their department's resources
                if user_dept == resource_dept or resource_dept == '':
                    return {
                        'allow': True,
                        'reason': 'Manager access granted during office hours'
                    }
                else:
                    return {
                        'allow': False,
                        'reason': 'Manager can only access own department resources'
                    }
            else:
                return {
                    'allow': False,
                    'reason': 'Manager access denied outside office hours (9 AM - 6 PM)'
                }
        
        # Rule 3: Employee can only access their department's data
        if role == 'employee':
            if action == 'read':
                if user_dept == resource_dept:
                    return {
                        'allow': True,
                        'reason': 'Employee can read own department data'
                    }
                else:
                    return {
                        'allow': False,
                        'reason': 'Employee cannot access other department data'
                    }
            else:
                return {
                    'allow': False,
                    'reason': 'Employee can only read, not write or delete'
                }
        
        # Default: Deny access
        return {
            'allow': False,
            'reason': 'Access denied: No matching policy rule'
        }
    
    def load_policy(self, policy_name, policy_code):
        """
        Load a Rego policy into OPA.
        
        Args:
            policy_name (str): Name/identifier for the policy
            policy_code (str): Rego policy code
        
        Returns:
            bool: True if policy loaded successfully
        """
        try:
            url = f"{self.opa_url}/v1/policies/{policy_name}"
            
            response = requests.put(
                url,
                data=policy_code,
                headers={'Content-Type': 'text/plain'},
                timeout=5
            )
            
            return response.status_code in [200, 201]
        except Exception as e:
            print(f"Error loading policy: {e}")
            return False
    
    def delete_policy(self, policy_name):
        """
        Delete a policy from OPA.
        
        Args:
            policy_name (str): Name of policy to delete
        
        Returns:
            bool: True if policy deleted successfully
        """
        try:
            url = f"{self.opa_url}/v1/policies/{policy_name}"
            response = requests.delete(url, timeout=5)
            return response.status_code in [200, 204]
        except Exception as e:
            print(f"Error deleting policy: {e}")
            return False
    
    def list_policies(self):
        """
        List all policies loaded in OPA.
        
        Returns:
            list: List of policy identifiers
        """
        try:
            url = f"{self.opa_url}/v1/policies"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                return [p['id'] for p in result.get('result', [])]
            return []
        except Exception:
            return []
    
    def health_check(self):
        """
        Check if OPA server is running and healthy.
        
        Returns:
            dict: Health status with 'healthy' boolean and 'message'
        """
        try:
            url = f"{self.opa_url}/health"
            response = requests.get(url, timeout=2)
            
            if response.status_code == 200:
                return {
                    'healthy': True,
                    'message': 'OPA server is running'
                }
            else:
                return {
                    'healthy': False,
                    'message': f'OPA server returned status {response.status_code}'
                }
        except requests.exceptions.ConnectionError:
            return {
                'healthy': False,
                'message': 'OPA server is not reachable (using local fallback)'
            }
        except Exception as e:
            return {
                'healthy': False,
                'message': str(e)
            }


# Global OPA client instance
opa_client = OPAClient()


def get_opa_client():
    """
    Get the OPA client instance.
    Configures the client with settings from Flask app config.
    """
    try:
        opa_url = current_app.config.get('OPA_SERVER_URL', 'http://localhost:8181')
        opa_client.opa_url = opa_url
    except RuntimeError:
        # Outside of application context
        pass
    return opa_client


def require_authorization(action, resource_type):
    """
    Decorator for protecting endpoints with OPA authorization.
    
    This decorator:
    1. Extracts user attributes from JWT token
    2. Builds authorization request
    3. Sends request to OPA
    4. Allows or denies access based on policy decision
    
    Args:
        action (str): Action being performed (read, write, delete)
        resource_type (str): Type of resource being accessed
    
    Usage:
        @app.route('/api/documents')
        @jwt_required()
        @require_authorization('read', 'document')
        def get_documents():
            return documents
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask_jwt_extended import get_jwt_identity, get_jwt
            from flask import request, jsonify
            from app.models import User, AuditLog
            from app import db
            
            # Get current user from JWT
            current_user_id = get_jwt_identity()
            jwt_claims = get_jwt()
            
            user = User.query.get(current_user_id)
            if not user:
                return jsonify({
                    'status': 'error',
                    'message': 'User not found'
                }), 404
            
            # Build authorization request for OPA
            input_data = {
                'user': user.get_attributes(),
                'action': action,
                'resource': {
                    'type': resource_type,
                    'department': kwargs.get('department', ''),
                    'id': kwargs.get('resource_id', '')
                },
                'environment': {
                    'time': datetime.now().strftime('%H:%M'),
                    'hour': datetime.now().hour,
                    'day': datetime.now().strftime('%A'),
                    'ip': request.remote_addr
                }
            }
            
            # Evaluate policy
            client = get_opa_client()
            result = client.evaluate_policy(input_data)
            
            # Log the authorization decision
            audit_log = AuditLog(
                user_id=user.id,
                username=user.username,
                action=action,
                resource=f"{resource_type}:{kwargs.get('resource_id', 'all')}",
                resource_type=resource_type,
                decision='allow' if result['allow'] else 'deny',
                reason=result.get('reason', ''),
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string[:200] if request.user_agent.string else None,
                request_data=json.dumps(input_data)
            )
            db.session.add(audit_log)
            db.session.commit()
            
            # Enforce decision
            if result['allow']:
                return f(*args, **kwargs)
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Access denied',
                    'reason': result.get('reason', 'Policy evaluation denied access')
                }), 403
        
        return decorated_function
    return decorator
