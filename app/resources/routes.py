"""
Protected Resources Routes
==========================
Sample protected endpoints that demonstrate OPA-based authorization.

These endpoints simulate real-world resources that require authorization:
- Documents: Department-specific documents
- Reports: Financial and operational reports  
- Settings: Application configuration

Each endpoint uses the OPA authorization decorator to enforce policies.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app import db
from app.models import User, AuditLog
from app.opa_client import get_opa_client, require_authorization
from datetime import datetime
import json

resources_bp = Blueprint('resources', __name__)


# Sample data to simulate protected resources
SAMPLE_DOCUMENTS = {
    'engineering': [
        {'id': 'doc-001', 'title': 'API Design Guidelines', 'department': 'engineering', 'content': 'Best practices for RESTful API design...'},
        {'id': 'doc-002', 'title': 'Code Review Checklist', 'department': 'engineering', 'content': 'Mandatory items to check during code review...'},
        {'id': 'doc-003', 'title': 'Deployment Procedures', 'department': 'engineering', 'content': 'Step-by-step deployment guide...'}
    ],
    'hr': [
        {'id': 'doc-004', 'title': 'Employee Handbook', 'department': 'hr', 'content': 'Company policies and procedures...'},
        {'id': 'doc-005', 'title': 'Leave Policy', 'department': 'hr', 'content': 'Annual leave and sick leave policies...'},
        {'id': 'doc-006', 'title': 'Performance Review Template', 'department': 'hr', 'content': 'Quarterly performance evaluation form...'}
    ],
    'finance': [
        {'id': 'doc-007', 'title': 'Budget Report Q1', 'department': 'finance', 'content': 'Quarterly budget analysis...'},
        {'id': 'doc-008', 'title': 'Expense Guidelines', 'department': 'finance', 'content': 'Reimbursement policies...'},
        {'id': 'doc-009', 'title': 'Audit Compliance', 'department': 'finance', 'content': 'Internal audit requirements...'}
    ]
}

SAMPLE_REPORTS = [
    {'id': 'rpt-001', 'title': 'Monthly Sales Report', 'type': 'sales', 'sensitive': False},
    {'id': 'rpt-002', 'title': 'Employee Performance Summary', 'type': 'hr', 'sensitive': True},
    {'id': 'rpt-003', 'title': 'Financial Statement', 'type': 'finance', 'sensitive': True},
    {'id': 'rpt-004', 'title': 'System Health Dashboard', 'type': 'engineering', 'sensitive': False}
]


def check_authorization(user, action, resource_type, resource_dept=''):
    """
    Helper function to check authorization via OPA.
    
    Args:
        user: User object
        action: Action being performed (read, write, delete)
        resource_type: Type of resource
        resource_dept: Department of the resource (optional)
    
    Returns:
        tuple: (allowed: bool, reason: str)
    """
    input_data = {
        'user': user.get_attributes(),
        'action': action,
        'resource': {
            'type': resource_type,
            'department': resource_dept
        },
        'environment': {
            'time': datetime.now().strftime('%H:%M'),
            'hour': datetime.now().hour,
            'day': datetime.now().strftime('%A'),
            'ip': request.remote_addr
        }
    }
    
    opa_client = get_opa_client()
    result = opa_client.evaluate_policy(input_data)
    
    # Log the decision
    audit_log = AuditLog(
        user_id=user.id,
        username=user.username,
        action=action,
        resource=f"{resource_type}:{resource_dept or 'all'}",
        resource_type=resource_type,
        decision='allow' if result['allow'] else 'deny',
        reason=result.get('reason', ''),
        ip_address=request.remote_addr,
        request_data=json.dumps(input_data)
    )
    db.session.add(audit_log)
    db.session.commit()
    
    return result['allow'], result.get('reason', '')


@resources_bp.route('/data', methods=['GET'])
@jwt_required()
def get_data():
    """
    Get Protected Data
    
    Returns data based on user's authorization level.
    Demonstrates dynamic authorization based on user attributes.
    
    Query Parameters:
        - department: Filter by department (optional)
        - type: Resource type - 'document' or 'report' (default: 'document')
    
    Returns:
        200: Authorized data
        403: Access denied with reason
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({
            'status': 'error',
            'message': 'User not found'
        }), 404
    
    resource_type = request.args.get('type', 'document')
    requested_dept = request.args.get('department', '')
    
    # Check authorization
    allowed, reason = check_authorization(user, 'read', resource_type, requested_dept)
    
    if not allowed:
        return jsonify({
            'status': 'error',
            'message': 'Access denied',
            'reason': reason,
            'user_info': {
                'role': user.role,
                'department': user.department
            }
        }), 403
    
    # Return data based on authorization
    if resource_type == 'document':
        if user.role == 'admin':
            # Admin gets all documents
            all_docs = []
            for dept_docs in SAMPLE_DOCUMENTS.values():
                all_docs.extend(dept_docs)
            data = all_docs
        elif requested_dept:
            # Filter by requested department
            data = SAMPLE_DOCUMENTS.get(requested_dept, [])
        else:
            # Return user's department documents
            data = SAMPLE_DOCUMENTS.get(user.department, [])
    else:
        # Reports
        if user.role == 'admin':
            data = SAMPLE_REPORTS
        else:
            # Non-admins only see non-sensitive reports
            data = [r for r in SAMPLE_REPORTS if not r['sensitive']]
    
    return jsonify({
        'status': 'success',
        'data': {
            'resources': data,
            'total': len(data),
            'user_department': user.department,
            'resource_type': resource_type
        }
    }), 200


@resources_bp.route('/documents', methods=['GET'])
@jwt_required()
def get_documents():
    """
    Get Department Documents
    
    Returns documents accessible to the current user.
    
    Query Parameters:
        - department: Specific department (optional)
    
    Returns:
        200: List of documents
        403: Access denied
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    requested_dept = request.args.get('department', user.department)
    
    # Check authorization
    allowed, reason = check_authorization(user, 'read', 'document', requested_dept)
    
    if not allowed:
        return jsonify({
            'status': 'error',
            'message': 'Access denied',
            'reason': reason
        }), 403
    
    # Get documents
    if user.role == 'admin':
        if requested_dept and requested_dept in SAMPLE_DOCUMENTS:
            documents = SAMPLE_DOCUMENTS[requested_dept]
        else:
            documents = []
            for docs in SAMPLE_DOCUMENTS.values():
                documents.extend(docs)
    else:
        documents = SAMPLE_DOCUMENTS.get(requested_dept, [])
    
    return jsonify({
        'status': 'success',
        'data': {
            'documents': documents,
            'department': requested_dept,
            'total': len(documents)
        }
    }), 200


@resources_bp.route('/documents', methods=['POST'])
@jwt_required()
def create_document():
    """
    Create New Document
    
    Creates a new document in the specified department.
    Requires write permission.
    
    Request Body:
        {
            "title": "string",
            "content": "string",
            "department": "string (optional, defaults to user's department)"
        }
    
    Returns:
        201: Document created
        403: Access denied
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    data = request.get_json()
    department = data.get('department', user.department)
    
    # Check write authorization
    allowed, reason = check_authorization(user, 'write', 'document', department)
    
    if not allowed:
        return jsonify({
            'status': 'error',
            'message': 'Access denied',
            'reason': reason
        }), 403
    
    # Simulate document creation
    new_doc = {
        'id': f'doc-{datetime.now().strftime("%Y%m%d%H%M%S")}',
        'title': data.get('title', 'Untitled'),
        'content': data.get('content', ''),
        'department': department,
        'created_by': user.username,
        'created_at': datetime.now().isoformat()
    }
    
    return jsonify({
        'status': 'success',
        'message': 'Document created successfully',
        'data': {
            'document': new_doc
        }
    }), 201


@resources_bp.route('/documents/<doc_id>', methods=['DELETE'])
@jwt_required()
def delete_document(doc_id):
    """
    Delete Document
    
    Deletes a document. Requires delete permission.
    
    Args:
        doc_id: Document ID to delete
    
    Returns:
        200: Document deleted
        403: Access denied
        404: Document not found
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    # Find document
    doc_found = None
    doc_dept = ''
    for dept, docs in SAMPLE_DOCUMENTS.items():
        for doc in docs:
            if doc['id'] == doc_id:
                doc_found = doc
                doc_dept = dept
                break
    
    if not doc_found:
        return jsonify({
            'status': 'error',
            'message': 'Document not found'
        }), 404
    
    # Check delete authorization
    allowed, reason = check_authorization(user, 'delete', 'document', doc_dept)
    
    if not allowed:
        return jsonify({
            'status': 'error',
            'message': 'Access denied',
            'reason': reason
        }), 403
    
    return jsonify({
        'status': 'success',
        'message': 'Document deleted successfully',
        'data': {
            'deleted_id': doc_id
        }
    }), 200


@resources_bp.route('/reports', methods=['GET'])
@jwt_required()
def get_reports():
    """
    Get Reports
    
    Returns reports accessible to the current user.
    Sensitive reports require elevated permissions.
    
    Returns:
        200: List of reports
        403: Access denied
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    # Check authorization
    allowed, reason = check_authorization(user, 'read', 'report', '')
    
    if not allowed:
        return jsonify({
            'status': 'error',
            'message': 'Access denied',
            'reason': reason
        }), 403
    
    # Filter reports based on role
    if user.role == 'admin':
        reports = SAMPLE_REPORTS
    elif user.role == 'manager':
        # Managers can see non-sensitive and their department reports
        reports = [r for r in SAMPLE_REPORTS if not r['sensitive'] or r['type'] == user.department]
    else:
        # Employees only see non-sensitive
        reports = [r for r in SAMPLE_REPORTS if not r['sensitive']]
    
    return jsonify({
        'status': 'success',
        'data': {
            'reports': reports,
            'total': len(reports)
        }
    }), 200


@resources_bp.route('/settings', methods=['GET'])
@jwt_required()
def get_settings():
    """
    Get Application Settings
    
    Returns application settings. Admin only.
    
    Returns:
        200: Settings data
        403: Access denied
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    # Check authorization
    allowed, reason = check_authorization(user, 'read', 'settings', '')
    
    if not allowed:
        return jsonify({
            'status': 'error',
            'message': 'Access denied',
            'reason': reason
        }), 403
    
    settings = {
        'app_name': 'Policy-as-Code Platform',
        'version': '1.0.0',
        'features': {
            'opa_enabled': True,
            'audit_logging': True,
            'jwt_expiry_hours': 1
        }
    }
    
    return jsonify({
        'status': 'success',
        'data': {
            'settings': settings
        }
    }), 200


@resources_bp.route('/settings', methods=['PUT'])
@jwt_required()
def update_settings():
    """
    Update Application Settings
    
    Updates application settings. Admin only with write permission.
    
    Returns:
        200: Settings updated
        403: Access denied
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    # Check authorization
    allowed, reason = check_authorization(user, 'write', 'settings', '')
    
    if not allowed:
        return jsonify({
            'status': 'error',
            'message': 'Access denied',
            'reason': reason
        }), 403
    
    data = request.get_json()
    
    return jsonify({
        'status': 'success',
        'message': 'Settings updated successfully',
        'data': {
            'updated_fields': list(data.keys()) if data else []
        }
    }), 200
