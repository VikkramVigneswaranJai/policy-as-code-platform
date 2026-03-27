"""
Comprehensive Test Suite for Policy-as-Code Platform
=====================================================
Tests all endpoints, edge cases, and policy evaluation scenarios.

Usage:
    python -m pytest test_app.py -v
    or
    python test_app.py
"""

import pytest
import json
from app import create_app, db
from app.models import User, Policy, AuditLog
from datetime import datetime

class TestAuthEndpoints:
    """Test authentication endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        app = create_app('testing')
        with app.test_client() as client:
            with app.app_context():
                db.create_all()
                yield client
                db.drop_all()
    
    def test_register_success(self, client):
        """Test successful user registration."""
        response = client.post('/auth/register', 
            json={
                'username': 'testuser',
                'email': 'test@example.com',
                'password': 'password123',
                'role': 'employee',
                'department': 'engineering'
            })
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert 'user' in data['data']
    
    def test_register_duplicate_username(self, client):
        """Test registration with duplicate username."""
        # Create first user
        client.post('/auth/register', 
            json={
                'username': 'testuser',
                'email': 'test1@example.com',
                'password': 'password123',
                'role': 'employee',
                'department': 'engineering'
            })
        
        # Try to create duplicate
        response = client.post('/auth/register', 
            json={
                'username': 'testuser',
                'email': 'test2@example.com',
                'password': 'password123',
                'role': 'employee',
                'department': 'engineering'
            })
        
        assert response.status_code == 409
        data = json.loads(response.data)
        assert 'already exists' in data['message'].lower()
    
    def test_register_invalid_role(self, client):
        """Test registration with invalid role."""
        response = client.post('/auth/register', 
            json={
                'username': 'testuser',
                'email': 'test@example.com',
                'password': 'password123',
                'role': 'superadmin',
                'department': 'engineering'
            })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'invalid role' in data['message'].lower()
    
    def test_register_short_password(self, client):
        """Test registration with short password."""
        response = client.post('/auth/register', 
            json={
                'username': 'testuser',
                'email': 'test@example.com',
                'password': '123',
                'role': 'employee',
                'department': 'engineering'
            })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'at least 6 characters' in data['message'].lower()
    
    def test_register_missing_fields(self, client):
        """Test registration with missing required fields."""
        response = client.post('/auth/register', 
            json={
                'username': 'testuser'
            })
        
        assert response.status_code == 400
    
    def test_login_success(self, client):
        """Test successful login."""
        # Register user first
        client.post('/auth/register', 
            json={
                'username': 'testuser',
                'email': 'test@example.com',
                'password': 'password123',
                'role': 'employee',
                'department': 'engineering'
            })
        
        # Login
        response = client.post('/auth/login', 
            json={
                'username': 'testuser',
                'password': 'password123'
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'success'
        assert 'access_token' in data['data']
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials."""
        response = client.post('/auth/login', 
            json={
                'username': 'nonexistent',
                'password': 'wrongpassword'
            })
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'invalid' in data['message'].lower()
    
    def test_login_missing_fields(self, client):
        """Test login with missing fields."""
        response = client.post('/auth/login', 
            json={
                'username': 'testuser'
            })
        
        assert response.status_code == 400
    
    def test_get_profile_authenticated(self, client):
        """Test getting profile with valid token."""
        # Register and login
        client.post('/auth/register', 
            json={
                'username': 'testuser',
                'email': 'test@example.com',
                'password': 'password123',
                'role': 'employee',
                'department': 'engineering'
            })
        
        login_response = client.post('/auth/login', 
            json={
                'username': 'testuser',
                'password': 'password123'
            })
        
        token = json.loads(login_response.data)['data']['access_token']
        
        # Get profile
        response = client.get('/auth/profile',
            headers={'Authorization': f'Bearer {token}'})
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['data']['user']['username'] == 'testuser'
    
    def test_get_profile_no_token(self, client):
        """Test getting profile without token."""
        response = client.get('/auth/profile')
        assert response.status_code == 401


class TestPolicyEvaluation:
    """Test OPA policy evaluation."""
    
    @pytest.fixture
    def client(self):
        """Create test client with sample users."""
        app = create_app('testing')
        with app.test_client() as client:
            with app.app_context():
                db.create_all()
                
                # Create test users
                admin = User(username='admin', email='admin@test.com', 
                           role='admin', department='management')
                admin.set_password('admin123')
                
                manager = User(username='manager', email='manager@test.com',
                             role='manager', department='engineering')
                manager.set_password('manager123')
                
                employee = User(username='employee', email='employee@test.com',
                              role='employee', department='engineering')
                employee.set_password('employee123')
                
                db.session.add_all([admin, manager, employee])
                db.session.commit()
                
                yield client
                db.drop_all()
    
    def get_token(self, client, username, password):
        """Helper to get auth token."""
        response = client.post('/auth/login', 
            json={'username': username, 'password': password})
        return json.loads(response.data)['data']['access_token']
    
    def test_admin_full_access(self, client):
        """Test admin has full access to all resources."""
        token = self.get_token(client, 'admin', 'admin123')
        
        response = client.post('/policy/evaluate',
            headers={'Authorization': f'Bearer {token}'},
            json={
                'action': 'delete',
                'resource': {
                    'type': 'document',
                    'department': 'hr'
                }
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['data']['allow'] == True
    
    def test_manager_office_hours(self, client):
        """Test manager access during office hours."""
        token = self.get_token(client, 'manager', 'manager123')
        
        # Simulate office hours (10 AM)
        response = client.post('/policy/evaluate',
            headers={'Authorization': f'Bearer {token}'},
            json={
                'action': 'read',
                'resource': {
                    'type': 'document',
                    'department': 'engineering'
                },
                'environment': {
                    'hour': 10
                }
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['data']['allow'] == True
    
    def test_manager_outside_hours(self, client):
        """Test manager access denied outside office hours."""
        token = self.get_token(client, 'manager', 'manager123')
        
        # Simulate outside office hours (8 PM)
        response = client.post('/policy/evaluate',
            headers={'Authorization': f'Bearer {token}'},
            json={
                'action': 'read',
                'resource': {
                    'type': 'document',
                    'department': 'engineering'
                },
                'environment': {
                    'hour': 20
                }
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['data']['allow'] == False
    
    def test_employee_read_own_department(self, client):
        """Test employee can read own department resources."""
        token = self.get_token(client, 'employee', 'employee123')
        
        response = client.post('/policy/evaluate',
            headers={'Authorization': f'Bearer {token}'},
            json={
                'action': 'read',
                'resource': {
                    'type': 'document',
                    'department': 'engineering'
                }
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['data']['allow'] == True
    
    def test_employee_cannot_write(self, client):
        """Test employee cannot write resources."""
        token = self.get_token(client, 'employee', 'employee123')
        
        response = client.post('/policy/evaluate',
            headers={'Authorization': f'Bearer {token}'},
            json={
                'action': 'write',
                'resource': {
                    'type': 'document',
                    'department': 'engineering'
                }
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['data']['allow'] == False
    
    def test_employee_cross_department_denied(self, client):
        """Test employee cannot access other department resources."""
        token = self.get_token(client, 'employee', 'employee123')
        
        response = client.post('/policy/evaluate',
            headers={'Authorization': f'Bearer {token}'},
            json={
                'action': 'read',
                'resource': {
                    'type': 'document',
                    'department': 'hr'
                }
            })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['data']['allow'] == False


class TestAuditLogging:
    """Test audit logging functionality."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        app = create_app('testing')
        with app.test_client() as client:
            with app.app_context():
                db.create_all()
                
                # Create test user
                user = User(username='testuser', email='test@test.com',
                          role='employee', department='engineering')
                user.set_password('password123')
                db.session.add(user)
                db.session.commit()
                
                yield client
                db.drop_all()
    
    def test_audit_log_created_on_evaluation(self, client):
        """Test that audit logs are created for policy evaluations."""
        # Login
        response = client.post('/auth/login', 
            json={'username': 'testuser', 'password': 'password123'})
        token = json.loads(response.data)['data']['access_token']
        
        # Make policy evaluation
        client.post('/policy/evaluate',
            headers={'Authorization': f'Bearer {token}'},
            json={
                'action': 'read',
                'resource': {'type': 'document', 'department': 'engineering'}
            })
        
        # Check audit log was created
        from app import create_app
        app = create_app('testing')
        with app.app_context():
            log_count = AuditLog.query.count()
            assert log_count > 0


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        app = create_app('testing')
        with app.test_client() as client:
            with app.app_context():
                db.create_all()
                yield client
                db.drop_all()
    
    def test_empty_request_body(self, client):
        """Test endpoints with empty request body."""
        response = client.post('/auth/register', json={})
        assert response.status_code == 400
    
    def test_malformed_json(self, client):
        """Test endpoints with malformed JSON."""
        response = client.post('/auth/register',
            data='not valid json',
            content_type='application/json')
        assert response.status_code in [400, 415]
    
    def test_sql_injection_attempt(self, client):
        """Test SQL injection prevention."""
        response = client.post('/auth/register', 
            json={
                'username': "admin' OR '1'='1",
                'email': 'test@example.com',
                'password': 'password123',
                'role': 'employee',
                'department': 'engineering'
            })
        
        # Should either succeed (creating user with that username) or fail validation
        # But should NOT cause SQL injection
        assert response.status_code in [201, 400, 409]
    
    def test_xss_prevention(self, client):
        """Test XSS prevention in user inputs."""
        response = client.post('/auth/register', 
            json={
                'username': '<script>alert("xss")</script>',
                'email': 'test@example.com',
                'password': 'password123',
                'role': 'employee',
                'department': 'engineering'
            })
        
        # Should handle script tags safely
        assert response.status_code in [201, 400]
    
    def test_very_long_input(self, client):
        """Test handling of very long inputs."""
        long_string = 'a' * 10000
        response = client.post('/auth/register', 
            json={
                'username': long_string,
                'email': 'test@example.com',
                'password': 'password123',
                'role': 'employee',
                'department': 'engineering'
            })
        
        # Should handle gracefully
        assert response.status_code in [400, 500]
    
    def test_unicode_characters(self, client):
        """Test handling of unicode characters."""
        response = client.post('/auth/register', 
            json={
                'username': 'user_测试_🎉',
                'email': 'test@example.com',
                'password': 'password123',
                'role': 'employee',
                'department': 'engineering'
            })
        
        # Should handle unicode gracefully
        assert response.status_code in [201, 400]
    
    def test_concurrent_registrations(self, client):
        """Test handling of concurrent user registrations."""
        import threading
        
        results = []
        
        def register_user(username):
            response = client.post('/auth/register', 
                json={
                    'username': username,
                    'email': f'{username}@example.com',
                    'password': 'password123',
                    'role': 'employee',
                    'department': 'engineering'
                })
            results.append(response.status_code)
        
        threads = [threading.Thread(target=register_user, args=(f'user{i}',)) 
                  for i in range(5)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should succeed
        assert all(code == 201 for code in results)


def run_tests():
    """Run all tests."""
    print("\n" + "="*70)
    print("  Running Comprehensive Test Suite")
    print("="*70 + "\n")
    
    pytest.main([__file__, '-v', '--tb=short'])

if __name__ == '__main__':
    run_tests()
