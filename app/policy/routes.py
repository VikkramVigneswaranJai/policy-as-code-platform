"""
Policy Management Routes
========================
API endpoints for managing Rego policies and evaluating authorization requests.

Endpoints:
- POST /policy/evaluate - Evaluate an authorization request
- GET /policy/list - List all policies
- POST /policy/create - Create a new policy
- PUT /policy/update/<id> - Update an existing policy
- PUT /policy/toggle/<id> - Enable/disable a policy
- DELETE /policy/delete/<id> - Delete a policy
- GET /policy/opa-status - Check OPA server status
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app import db
from app.models import User, Policy, AuditLog
from app.opa_client import get_opa_client
from datetime import datetime
import json

policy_bp = Blueprint('policy', __name__)


@policy_bp.route('/evaluate', methods=['POST'])
@jwt_required()
def evaluate_policy():
    """
    Evaluate Authorization Request
    
    Sends an authorization request to OPA for policy evaluation.
    This is the core endpoint that demonstrates Policy-as-Code in action.
    
    Request Body (JSON):
        {
            "action": "string (required) - read, write, delete",
            "resource": {
                "type": "string (required) - document, report, settings",
                "department": "string (optional)",
                "id": "string (optional)"
            }
        }
    
    The user attributes are automatically extracted from the JWT token.
    Environment data (time, IP) is captured automatically.
    
    Returns:
        200: Authorization decision (allow/deny with reason)
        400: Invalid request
        401: Missing or invalid token
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({
            'status': 'error',
            'message': 'User not found'
        }), 404
    
    data = request.get_json()
    
    if not data:
        return jsonify({
            'status': 'error',
            'message': 'Request body is required'
        }), 400
    
    if not data.get('action'):
        return jsonify({
            'status': 'error',
            'message': 'action is required'
        }), 400
    
    if not data.get('resource'):
        return jsonify({
            'status': 'error',
            'message': 'resource is required'
        }), 400
    
    # Build OPA input data
    # This structure matches what our Rego policies expect
    input_data = {
        'user': user.get_attributes(),
        'action': data['action'],
        'resource': {
            'type': data['resource'].get('type', 'unknown'),
            'department': data['resource'].get('department', ''),
            'id': data['resource'].get('id', '')
        },
        'environment': {
            'time': datetime.now().strftime('%H:%M'),
            'hour': datetime.now().hour,
            'day': datetime.now().strftime('%A'),
            'ip': request.remote_addr
        }
    }
    
    # Evaluate policy via OPA
    opa_client = get_opa_client()
    result = opa_client.evaluate_policy(input_data)
    
    # Log the authorization decision
    audit_log = AuditLog(
        user_id=user.id,
        username=user.username,
        action=data['action'],
        resource=f"{data['resource'].get('type', 'unknown')}:{data['resource'].get('id', 'all')}",
        resource_type=data['resource'].get('type', 'unknown'),
        decision='allow' if result['allow'] else 'deny',
        reason=result.get('reason', ''),
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string[:200] if request.user_agent.string else None,
        request_data=json.dumps(input_data)
    )
    db.session.add(audit_log)
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'data': {
            'decision': 'allow' if result['allow'] else 'deny',
            'allowed': result['allow'],
            'reason': result.get('reason', ''),
            'input': input_data,
            'audit_id': audit_log.id
        }
    }), 200


@policy_bp.route('/list', methods=['GET'])
@jwt_required()
def list_policies():
    """
    List All Policies
    
    Returns all policies stored in the database.
    Can filter by status (active/inactive).
    
    Query Parameters:
        - status: 'active', 'inactive', or 'all' (default: 'all')
    
    Returns:
        200: List of policies
    """
    status_filter = request.args.get('status', 'all')
    
    query = Policy.query
    
    if status_filter == 'active':
        query = query.filter_by(is_active=True)
    elif status_filter == 'inactive':
        query = query.filter_by(is_active=False)
    
    policies = query.order_by(Policy.created_at.desc()).all()
    
    return jsonify({
        'status': 'success',
        'data': {
            'policies': [policy.to_dict() for policy in policies],
            'total': len(policies)
        }
    }), 200


@policy_bp.route('/create', methods=['POST'])
@jwt_required()
def create_policy():
    """
    Create New Policy
    
    Creates a new Rego policy and optionally loads it into OPA.
    Only admin users can create policies.
    
    Request Body (JSON):
        {
            "name": "string (required) - unique policy name",
            "description": "string (optional)",
            "policy_code": "string (required) - Rego policy code",
            "version": "string (optional, default: '1.0.0')",
            "is_active": "boolean (optional, default: true)"
        }
    
    Returns:
        201: Policy created successfully
        400: Validation error
        403: Access denied (non-admin)
        409: Policy name already exists
    """
    jwt_claims = get_jwt()
    current_user_id = get_jwt_identity()
    
    if jwt_claims.get('role') != 'admin':
        return jsonify({
            'status': 'error',
            'message': 'Admin access required to create policies'
        }), 403
    
    data = request.get_json()
    
    if not data:
        return jsonify({
            'status': 'error',
            'message': 'Request body is required'
        }), 400
    
    # Validate required fields
    if not data.get('name'):
        return jsonify({
            'status': 'error',
            'message': 'Policy name is required'
        }), 400
    
    if not data.get('policy_code'):
        return jsonify({
            'status': 'error',
            'message': 'Policy code is required'
        }), 400
    
    # Check for duplicate name
    if Policy.query.filter_by(name=data['name']).first():
        return jsonify({
            'status': 'error',
            'message': 'Policy with this name already exists'
        }), 409
    
    # Create policy
    policy = Policy(
        name=data['name'],
        description=data.get('description', ''),
        policy_code=data['policy_code'],
        version=data.get('version', '1.0.0'),
        is_active=data.get('is_active', True),
        created_by=current_user_id
    )
    
    try:
        db.session.add(policy)
        db.session.commit()
        
        # Load policy into OPA if active
        if policy.is_active:
            opa_client = get_opa_client()
            opa_client.load_policy(policy.name, policy.policy_code)
        
        return jsonify({
            'status': 'success',
            'message': 'Policy created successfully',
            'data': {
                'policy': policy.to_dict()
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to create policy: {str(e)}'
        }), 500


@policy_bp.route('/update/<int:policy_id>', methods=['PUT'])
@jwt_required()
def update_policy(policy_id):
    """
    Update Existing Policy
    
    Updates a policy's code, description, or version.
    This enables dynamic policy updates without application restart.
    Only admin users can update policies.
    
    Args:
        policy_id: ID of the policy to update
    
    Request Body (JSON):
        {
            "description": "string (optional)",
            "policy_code": "string (optional)",
            "version": "string (optional)"
        }
    
    Returns:
        200: Policy updated successfully
        403: Access denied
        404: Policy not found
    """
    jwt_claims = get_jwt()
    
    if jwt_claims.get('role') != 'admin':
        return jsonify({
            'status': 'error',
            'message': 'Admin access required to update policies'
        }), 403
    
    policy = Policy.query.get(policy_id)
    if not policy:
        return jsonify({
            'status': 'error',
            'message': 'Policy not found'
        }), 404
    
    data = request.get_json()
    
    # Update fields if provided
    if 'description' in data:
        policy.description = data['description']
    
    if 'policy_code' in data:
        policy.policy_code = data['policy_code']
    
    if 'version' in data:
        policy.version = data['version']
    
    try:
        db.session.commit()
        
        # Reload policy in OPA if active
        if policy.is_active and 'policy_code' in data:
            opa_client = get_opa_client()
            opa_client.load_policy(policy.name, policy.policy_code)
        
        return jsonify({
            'status': 'success',
            'message': 'Policy updated successfully',
            'data': {
                'policy': policy.to_dict()
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to update policy: {str(e)}'
        }), 500


@policy_bp.route('/toggle/<int:policy_id>', methods=['PUT'])
@jwt_required()
def toggle_policy(policy_id):
    """
    Enable/Disable Policy
    
    Toggles a policy's active status.
    When disabled, the policy is removed from OPA.
    When enabled, the policy is loaded into OPA.
    
    Args:
        policy_id: ID of the policy to toggle
    
    Returns:
        200: Policy toggled successfully
        403: Access denied
        404: Policy not found
    """
    jwt_claims = get_jwt()
    
    if jwt_claims.get('role') != 'admin':
        return jsonify({
            'status': 'error',
            'message': 'Admin access required'
        }), 403
    
    policy = Policy.query.get(policy_id)
    if not policy:
        return jsonify({
            'status': 'error',
            'message': 'Policy not found'
        }), 404
    
    # Toggle status
    policy.is_active = not policy.is_active
    
    try:
        db.session.commit()
        
        opa_client = get_opa_client()
        if policy.is_active:
            # Load policy into OPA
            opa_client.load_policy(policy.name, policy.policy_code)
        else:
            # Remove policy from OPA
            opa_client.delete_policy(policy.name)
        
        return jsonify({
            'status': 'success',
            'message': f'Policy {"enabled" if policy.is_active else "disabled"} successfully',
            'data': {
                'policy': policy.to_dict()
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to toggle policy: {str(e)}'
        }), 500


@policy_bp.route('/delete/<int:policy_id>', methods=['DELETE'])
@jwt_required()
def delete_policy(policy_id):
    """
    Delete Policy
    
    Permanently removes a policy from the database and OPA.
    Only admin users can delete policies.
    
    Args:
        policy_id: ID of the policy to delete
    
    Returns:
        200: Policy deleted successfully
        403: Access denied
        404: Policy not found
    """
    jwt_claims = get_jwt()
    
    if jwt_claims.get('role') != 'admin':
        return jsonify({
            'status': 'error',
            'message': 'Admin access required'
        }), 403
    
    policy = Policy.query.get(policy_id)
    if not policy:
        return jsonify({
            'status': 'error',
            'message': 'Policy not found'
        }), 404
    
    policy_name = policy.name
    
    try:
        # Remove from OPA first
        opa_client = get_opa_client()
        opa_client.delete_policy(policy_name)
        
        # Delete from database
        db.session.delete(policy)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Policy deleted successfully'
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Failed to delete policy: {str(e)}'
        }), 500


@policy_bp.route('/opa-status', methods=['GET'])
@jwt_required()
def opa_status():
    """
    Check OPA Server Status
    
    Returns the health status of the OPA policy engine.
    Also lists currently loaded policies.
    
    Returns:
        200: OPA status information
    """
    opa_client = get_opa_client()
    health = opa_client.health_check()
    loaded_policies = opa_client.list_policies()
    
    return jsonify({
        'status': 'success',
        'data': {
            'opa_healthy': health['healthy'],
            'opa_message': health['message'],
            'loaded_policies': loaded_policies,
            'opa_url': opa_client.opa_url
        }
    }), 200


@policy_bp.route('/<int:policy_id>', methods=['GET'])
@jwt_required()
def get_policy(policy_id):
    """
    Get Single Policy
    
    Returns details of a specific policy.
    
    Args:
        policy_id: ID of the policy
    
    Returns:
        200: Policy details
        404: Policy not found
    """
    policy = Policy.query.get(policy_id)
    if not policy:
        return jsonify({
            'status': 'error',
            'message': 'Policy not found'
        }), 404
    
    return jsonify({
        'status': 'success',
        'data': {
            'policy': policy.to_dict()
        }
    }), 200
