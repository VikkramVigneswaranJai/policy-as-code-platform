from flask import Blueprint, request, jsonify, make_response
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
    set_access_cookies
)
from app import db
from app.models import User

auth_bp = Blueprint('auth', __name__)


# =========================
# REGISTER
# =========================
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data:
        return jsonify({'status': 'error', 'message': 'Request body is required'}), 400

    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'status': 'error', 'message': f'{field} is required'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'status': 'error', 'message': 'Username already exists'}), 409

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'status': 'error', 'message': 'Email already exists'}), 409

    if len(data['password']) < 6:
        return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400

    user = User(
        username=data['username'],
        email=data['email'],
        role=data.get('role', 'employee'),
        department=data.get('department', 'general'),
        designation=data.get('designation')
    )

    user.set_password(data['password'])

    db.session.add(user)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': 'User registered successfully',
        'data': {'user': user.to_dict()}
    }), 201


# =========================
# LOGIN (🔥 FIXED)
# =========================
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data:
        return jsonify({'status': 'error', 'message': 'Request body is required'}), 400

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password are required'}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({'status': 'error', 'message': 'Invalid username or password'}), 401

    if not user.is_active:
        return jsonify({'status': 'error', 'message': 'Account is deactivated'}), 401

    # JWT Claims
    additional_claims = {
        'role': user.role,
        'department': user.department,
        'designation': user.designation,
        'username': user.username
    }

    # 🔥 IMPORTANT: identity = username
    access_token = create_access_token(
        identity=user.username,
        additional_claims=additional_claims
    )

    # 🔥 STORE TOKEN IN COOKIE (CORRECT METHOD)
    response = make_response(jsonify({
        'status': 'success',
        'message': 'Login successful',
        'data': {
            'access_token': access_token,
            'token_type': 'Bearer',
            'user': user.to_dict()
        }
    }))

    set_access_cookies(response, access_token)

    return response


# =========================
# PROFILE
# =========================
@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_username = get_jwt_identity()

    user = User.query.filter_by(username=current_username).first()

    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    return jsonify({
        'status': 'success',
        'data': {'user': user.to_dict()}
    }), 200


# =========================
# LIST USERS
# =========================
@auth_bp.route('/users', methods=['GET'])
@jwt_required()
def list_users():
    jwt_claims = get_jwt()

    if jwt_claims.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403

    users = User.query.all()

    return jsonify({
        'status': 'success',
        'data': {
            'users': [user.to_dict() for user in users],
            'total': len(users)
        }
    }), 200


# =========================
# UPDATE USER
# =========================
@auth_bp.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    jwt_claims = get_jwt()

    if jwt_claims.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403

    user = User.query.get(user_id)

    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    data = request.get_json()

    if 'role' in data:
        user.role = data['role']

    if 'department' in data:
        user.department = data['department']

    if 'designation' in data:
        user.designation = data['designation']

    if 'is_active' in data:
        user.is_active = bool(data['is_active'])

    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': 'User updated successfully',
        'data': {'user': user.to_dict()}
    }), 200


# =========================
# DELETE USER
# =========================
@auth_bp.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    jwt_claims = get_jwt()

    if jwt_claims.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Admin access required'}), 403

    user = User.query.get(user_id)

    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': 'User deleted successfully'
    }), 200