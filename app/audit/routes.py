"""
Audit Log Routes
================
API endpoints for accessing authorization audit logs.

Audit logs record every authorization decision made by the system,
providing a complete trail for compliance and debugging.

Endpoints:
- GET /audit/logs - List all audit logs
- GET /audit/logs/<id> - Get specific log entry
- GET /audit/stats - Get authorization statistics
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from app import db
from app.models import AuditLog, User
from datetime import datetime, timedelta
from sqlalchemy import func

audit_bp = Blueprint('audit', __name__)


@audit_bp.route('/logs', methods=['GET'])
@jwt_required()
def get_audit_logs():
    """
    Get Audit Logs
    
    Returns authorization audit logs with optional filtering.
    Admin users can see all logs, others see only their own.
    
    Query Parameters:
        - page: Page number (default: 1)
        - per_page: Items per page (default: 20, max: 100)
        - decision: Filter by decision ('allow' or 'deny')
        - action: Filter by action ('read', 'write', 'delete')
        - user_id: Filter by user ID (admin only)
        - from_date: Start date (YYYY-MM-DD)
        - to_date: End date (YYYY-MM-DD)
    
    Returns:
        200: Paginated list of audit logs
    """
    current_user_id = get_jwt_identity()
    jwt_claims = get_jwt()
    is_admin = jwt_claims.get('role') == 'admin'
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    
    # Build query
    query = AuditLog.query
    
    # Non-admins can only see their own logs
    if not is_admin:
        query = query.filter_by(user_id=current_user_id)
    
    # Apply filters
    decision = request.args.get('decision')
    if decision in ['allow', 'deny']:
        query = query.filter_by(decision=decision)
    
    action = request.args.get('action')
    if action:
        query = query.filter_by(action=action)
    
    # Admin can filter by user_id
    if is_admin and request.args.get('user_id'):
        query = query.filter_by(user_id=request.args.get('user_id', type=int))
    
    # Date range filter
    from_date = request.args.get('from_date')
    if from_date:
        try:
            from_dt = datetime.strptime(from_date, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp >= from_dt)
        except ValueError:
            pass
    
    to_date = request.args.get('to_date')
    if to_date:
        try:
            to_dt = datetime.strptime(to_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AuditLog.timestamp < to_dt)
        except ValueError:
            pass
    
    # Order by most recent first
    query = query.order_by(AuditLog.timestamp.desc())
    
    # Paginate
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'status': 'success',
        'data': {
            'logs': [log.to_dict() for log in pagination.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_pages': pagination.pages,
                'total_items': pagination.total,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev
            }
        }
    }), 200


@audit_bp.route('/logs/<int:log_id>', methods=['GET'])
@jwt_required()
def get_audit_log(log_id):
    """
    Get Single Audit Log
    
    Returns details of a specific audit log entry.
    
    Args:
        log_id: ID of the audit log
    
    Returns:
        200: Audit log details
        403: Access denied
        404: Log not found
    """
    current_user_id = get_jwt_identity()
    jwt_claims = get_jwt()
    is_admin = jwt_claims.get('role') == 'admin'
    
    log = AuditLog.query.get(log_id)
    
    if not log:
        return jsonify({
            'status': 'error',
            'message': 'Audit log not found'
        }), 404
    
    # Non-admins can only see their own logs
    if not is_admin and log.user_id != current_user_id:
        return jsonify({
            'status': 'error',
            'message': 'Access denied'
        }), 403
    
    return jsonify({
        'status': 'success',
        'data': {
            'log': log.to_dict()
        }
    }), 200


@audit_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_audit_stats():
    """
    Get Authorization Statistics
    
    Returns aggregated statistics about authorization decisions.
    Admin only endpoint.
    
    Query Parameters:
        - days: Number of days to include (default: 7)
    
    Returns:
        200: Authorization statistics
        403: Access denied (non-admin)
    """
    jwt_claims = get_jwt()
    
    if jwt_claims.get('role') != 'admin':
        return jsonify({
            'status': 'error',
            'message': 'Admin access required'
        }), 403
    
    days = request.args.get('days', 7, type=int)
    since = datetime.utcnow() - timedelta(days=days)
    
    # Total decisions
    total_logs = AuditLog.query.filter(AuditLog.timestamp >= since).count()
    
    # Decisions by outcome
    allow_count = AuditLog.query.filter(
        AuditLog.timestamp >= since,
        AuditLog.decision == 'allow'
    ).count()
    
    deny_count = AuditLog.query.filter(
        AuditLog.timestamp >= since,
        AuditLog.decision == 'deny'
    ).count()
    
    # Decisions by action
    action_stats = db.session.query(
        AuditLog.action,
        func.count(AuditLog.id)
    ).filter(
        AuditLog.timestamp >= since
    ).group_by(AuditLog.action).all()
    
    # Decisions by resource type
    resource_stats = db.session.query(
        AuditLog.resource_type,
        func.count(AuditLog.id)
    ).filter(
        AuditLog.timestamp >= since
    ).group_by(AuditLog.resource_type).all()
    
    # Top denied users
    denied_users = db.session.query(
        AuditLog.username,
        func.count(AuditLog.id).label('deny_count')
    ).filter(
        AuditLog.timestamp >= since,
        AuditLog.decision == 'deny'
    ).group_by(AuditLog.username).order_by(
        func.count(AuditLog.id).desc()
    ).limit(5).all()
    
    return jsonify({
        'status': 'success',
        'data': {
            'period_days': days,
            'total_decisions': total_logs,
            'allowed': allow_count,
            'denied': deny_count,
            'allow_rate': round(allow_count / total_logs * 100, 2) if total_logs > 0 else 0,
            'by_action': {action: count for action, count in action_stats},
            'by_resource': {res: count for res, count in resource_stats if res},
            'top_denied_users': [{'username': u, 'count': c} for u, c in denied_users]
        }
    }), 200


@audit_bp.route('/export', methods=['GET'])
@jwt_required()
def export_audit_logs():
    """
    Export Audit Logs
    
    Exports audit logs as JSON for compliance reporting.
    Admin only endpoint.
    
    Query Parameters:
        - from_date: Start date (YYYY-MM-DD, required)
        - to_date: End date (YYYY-MM-DD, required)
    
    Returns:
        200: Exported logs
        400: Missing date parameters
        403: Access denied
    """
    jwt_claims = get_jwt()
    
    if jwt_claims.get('role') != 'admin':
        return jsonify({
            'status': 'error',
            'message': 'Admin access required'
        }), 403
    
    from_date = request.args.get('from_date')
    to_date = request.args.get('to_date')
    
    if not from_date or not to_date:
        return jsonify({
            'status': 'error',
            'message': 'Both from_date and to_date are required'
        }), 400
    
    try:
        from_dt = datetime.strptime(from_date, '%Y-%m-%d')
        to_dt = datetime.strptime(to_date, '%Y-%m-%d') + timedelta(days=1)
    except ValueError:
        return jsonify({
            'status': 'error',
            'message': 'Invalid date format. Use YYYY-MM-DD'
        }), 400
    
    logs = AuditLog.query.filter(
        AuditLog.timestamp >= from_dt,
        AuditLog.timestamp < to_dt
    ).order_by(AuditLog.timestamp).all()
    
    return jsonify({
        'status': 'success',
        'data': {
            'export_period': {
                'from': from_date,
                'to': to_date
            },
            'total_records': len(logs),
            'logs': [log.to_dict() for log in logs]
        }
    }), 200
