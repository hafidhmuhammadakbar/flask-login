import unittest
from flask import Flask, session, request, url_for
from main import app

class FlaskLoginTestCase(unittest.TestCase):

    def setUp(self):
        """Set up test client"""
        app.config['TESTING'] = True
        self.app = app.test_client()
        self.app_context = app.test_request_context()
        self.app_context.push()

    def tearDown(self):
        """Clean up after tests"""
        self.app_context.pop()

    def test_login(self):
        """Test login functionality"""
        with self.app as client:
            # Test login with valid credentials
            rv = client.post('/flasklogin/', data=dict(
                username='hafidhakb',
                password='hafidhakb'
            ), follow_redirects=True)
            self.assertEqual(rv.status_code, 200)
            self.assertIn(b'Logged in successfully', rv.data)

            # Test login with invalid credentials
            rv = client.post('/flasklogin/', data=dict(
                username='testuser',
                password='wrongpassword'
            ), follow_redirects=True)
            self.assertEqual(rv.status_code, 200)
            self.assertIn(b'Incorrect username or password', rv.data)

    def test_register(self):
        """Test registration functionality"""
        with self.app as client:
            # Test registration with valid data
            rv = client.post('/flasklogin/register', data=dict(
                name='Test User',
                username='newuser',
                password='newpassword',
                email='test@example.com'
            ), follow_redirects=True)
            self.assertEqual(rv.status_code, 200)
            self.assertIn(b'You have successfully registered!', rv.data)

            # Test registration with existing username
            rv = client.post('/flasklogin/register', data=dict(
                name='Test User',
                username='hafidhakb',  # Existing username
                password='newpassword',
                email='test2@example.com'
            ), follow_redirects=True)
            self.assertEqual(rv.status_code, 200)
            self.assertIn(b'Username already exists!', rv.data)

            # Test registration with existing email
            rv = client.post('/flasklogin/register', data=dict(
                name='Test User',
                username='newuser2',
                password='newpassword',
                email='hafidhakb@gmail.com'  # Existing email
            ), follow_redirects=True)
            self.assertEqual(rv.status_code, 200)
            self.assertIn(b'Email already exists!', rv.data)

            # Test registration with invalid email
            rv = client.post('/flasklogin/register', data=dict(
                name='Test User',
                username='newuser3',
                password='newpassword',
                email='invalidemail'
            ), follow_redirects=True)
            self.assertEqual(rv.status_code, 200)
            self.assertIn(b'Invalid email address!', rv.data)

if __name__ == '__main__':
    unittest.main()

