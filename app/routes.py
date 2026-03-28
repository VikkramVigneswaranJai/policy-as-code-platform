"""
Main Application Routes
=======================
Handles the admin dashboard and main application pages.
Serves HTML templates for the web interface.
"""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from flask_jwt_extended import get_jwt_identity, get_jwt, verify_jwt_in_request
from app import db
from app.models import User, Policy, AuditLog
from app.opa_client import get_opa_client
from functools import wraps
import logging

main_bp = Blueprint('main', __name__)


def admin_required(f):
    """
    Decorator to require admin role for web routes.
    Redirects to login page if not authenticated or not admin.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request(locations=['cookies', 'headers'])
            claims = get_jwt()
            if claims.get('role') != 'admin':
                return redirect(url_for('main.login_page'))
        except Exception:
            return redirect(url_for('main.login_page'))
        return f(*args, **kwargs)
    return decorated_function


def login_required(f):
    """
    Decorator to require login for web routes.
    Redirects to the homepage if the user is not authenticated.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request(locations=['cookies', 'headers'])
        except Exception:
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


@main_bp.route('/', methods=['GET'])
def index():
    """
    Landing Page
    
    Displays the main landing page with project information.
    """
    return render_template('index.html')


@main_bp.route('/login', methods=['GET', 'POST'])
def login_page():
    """
    Login Page
    
    Displays the login form for admin dashboard access.
    """
    return render_template('login.html')


@main_bp.route('/register', methods=['GET', 'POST'])
def register_page():
    """
    Registration Page
    
    Displays the registration form for new users.
    """
    return render_template('register.html')


@main_bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """
    Admin Dashboard
    
    Main dashboard showing system overview.
    """
    # Get statistics
    total_users = User.query.count()
    total_policies = Policy.query.count()
    active_policies = Policy.query.filter_by(is_active=True).count()
    total_logs = AuditLog.query.count()
    
    # Recent logs
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    
    # OPA status
    opa_client = get_opa_client()
    opa_health = opa_client.health_check()
    
    return render_template('dashboard.html',
        total_users=total_users,
        total_policies=total_policies,
        active_policies=active_policies,
        total_logs=total_logs,
        recent_logs=recent_logs,
        opa_healthy=opa_health['healthy'],
        opa_message=opa_health['message']
    )


@main_bp.route('/policies', methods=['GET'])
@login_required
def policies_page():
    """
    Policies Management Page
    
    Lists all policies with management options.
    """
    policies = Policy.query.order_by(Policy.created_at.desc()).all()
    return render_template('policies.html', policies=policies)


@main_bp.route('/policies/new', methods=['GET'])
@login_required
def new_policy_page():
    """
    New Policy Creation Page
    
    Form for creating a new Rego policy.
    """
    return render_template('policy_form.html', policy=None)


@main_bp.route('/policies/edit/<int:policy_id>', methods=['GET'])
@login_required
def edit_policy_page(policy_id):
    """
    Edit Policy Page
    
    Form for editing an existing policy.
    """
    policy = Policy.query.get_or_404(policy_id)
    return render_template('policy_form.html', policy=policy)


from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request


@main_bp.route('/users', methods=['GET'])
@login_required
def users_page():
    users = User.query.order_by(User.created_at.desc()).all()

    current_username = get_jwt_identity()
    current_user_role = None
    current_user = User.query.filter_by(username=current_username).first()
    if current_user:
        current_user_role = current_user.role
    logging.info(f"JWT USER: {current_username}")

    return render_template(
        'users.html',
        users=users,
        current_username=current_username,
        current_user_role=current_user_role
    )

@main_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == get_jwt_identity():
        flash('Cannot delete yourself', 'error')
        return redirect(url_for('main.users_page'))
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('main.users_page'))

@main_bp.route('/audit', methods=['GET'])
@login_required
def audit_page():
    """
    Audit Logs Page
    
    Displays authorization audit logs with filtering.
    """
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Build query with filters
    query = AuditLog.query
    
    decision = request.args.get('decision')
    if decision in ['allow', 'deny']:
        query = query.filter_by(decision=decision)
    
    action = request.args.get('action')
    if action:
        query = query.filter_by(action=action)
    
    # Paginate
    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('audit.html',
        logs=pagination.items,
        pagination=pagination,
        current_decision=decision,
        current_action=action
    )


@main_bp.route('/test', methods=['GET'])
def test_page():
    """
    Policy Testing Page
    
    Interactive page to test policy evaluation.
    """
    return render_template('test.html')


@main_bp.route('/api-docs', methods=['GET'])
def api_docs():
    """
    API Documentation Page
    
    Displays API endpoints and usage examples.
    """
    return render_template('api_docs.html')


@main_bp.route('/health', methods=['GET'])
def health_check():
    """
    Application Health Check
    
    Returns the health status of the application and its dependencies.
    """
    opa_client = get_opa_client()
    opa_health = opa_client.health_check()
    
    return jsonify({
        'status': 'healthy',
        'components': {
            'flask': True,
            'database': True,
            'opa': opa_health
        }
    }), 200
