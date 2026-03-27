"""
Policy-as-Code Platform - Application Factory
==============================================
This module initializes the Flask application using the Application Factory pattern.
This pattern allows for better testing and configuration management.
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS

from config import config_by_name

# Initialize extensions without binding to app
# This allows for late binding during app creation
db = SQLAlchemy()
jwt = JWTManager()


def create_app(config_name='default'):
    """
    Application Factory Function
    
    Creates and configures the Flask application instance.
    
    Args:
        config_name (str): Configuration to use ('development', 'production', 'testing')
    
    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    # Load configuration
    app.config.from_object(config_by_name[config_name])
    
    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)
    CORS(app)
    
    # Register blueprints (modular components)
    from app.auth.routes import auth_bp
    from app.policy.routes import policy_bp
    from app.resources.routes import resources_bp
    from app.audit.routes import audit_bp
    from app.routes import main_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(policy_bp, url_prefix='/policy')
    app.register_blueprint(resources_bp, url_prefix='/resource')
    app.register_blueprint(audit_bp, url_prefix='/audit')
    app.register_blueprint(main_bp)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # JWT error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return {
            'status': 'error',
            'message': 'Token has expired',
            'error': 'token_expired'
        }, 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return {
            'status': 'error',
            'message': 'Invalid token',
            'error': 'invalid_token'
        }, 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return {
            'status': 'error',
            'message': 'Authorization token is missing',
            'error': 'authorization_required'
        }, 401
    
    return app
