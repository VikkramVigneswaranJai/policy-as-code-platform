"""
Configuration Module for Policy-as-Code Platform
=================================================
This module contains all configuration settings for the Flask application,
including database settings, JWT configuration, and OPA server settings.
"""

import os
from datetime import timedelta

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """
    Base Configuration Class
    Contains default settings used across all environments.
    """
    
    # Flask Secret Key
    SECRET_KEY = os.environ.get(
        'SECRET_KEY', 
        'policy-as-code-secret-key-change-in-production'
    )
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 
        f'sqlite:///{os.path.join(BASE_DIR, "pac_platform.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # =========================
    # JWT CONFIG (🔥 FIXED)
    # =========================
    JWT_SECRET_KEY = os.environ.get(
        'JWT_SECRET_KEY', 
        'jwt-secret-key-change-in-production'
    )
    
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

    # 🔥 IMPORTANT CHANGE (COOKIE BASED)
    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_ACCESS_COOKIE_NAME = "access_token_cookie"
    JWT_COOKIE_SECURE = False
    JWT_COOKIE_CSRF_PROTECT = False

    # =========================
    # OPA CONFIG
    # =========================
    OPA_SERVER_URL = os.environ.get(
        'OPA_SERVER_URL', 
        'http://localhost:8181'
    )
    OPA_POLICY_PATH = os.path.join(BASE_DIR, 'opa_policies')
    
    # App settings
    DEBUG = False
    TESTING = False
    
    # CORS
    CORS_HEADERS = 'Content-Type'


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_ECHO = False
    
    SECRET_KEY = os.environ.get('SECRET_KEY')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)


# Config mapping
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}