# auth/tests.py
from django.core.cache import cache
from django.test import TestCase, Client, override_settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.utils import timezone
from rest_framework.test import APITestCase, APIClient
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.authtoken.models import Token
from rest_framework import status
from datetime import timedelta
from smtplib import SMTPException
from unittest.mock import patch
from .models import EmailVerificationToken, PasswordResetToken, LoginAttempt
from .services import AuthService

User = get_user_model()

class EmailVerificationTokenModelTest(TestCase):
    """Test EmailVerificationToken model."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!'
        )
        self.token = EmailVerificationToken.objects.create(
            user=self.user,
            token='123456',
            expires_at=timezone.now() + timedelta(hours=24)
        )
    
    def test_is_valid_when_not_expired(self):
        """Test token is valid when not expired."""
        self.assertTrue(self.token.is_valid())
    
    def test_is_invalid_when_expired(self):
        """Test token is invalid when expired."""
        self.token.expires_at = timezone.now() - timedelta(hours=1)
        self.token.save()
        self.assertFalse(self.token.is_valid())
    
    def test_is_invalid_when_used(self):
        """Test token is invalid when used."""
        self.token.is_used = True
        self.token.save()
        self.assertFalse(self.token.is_valid())
    
    def test_mark_used(self):
        """Test marking token as used."""
        self.assertFalse(self.token.is_used)
        self.token.mark_used()
        self.token.refresh_from_db()
        self.assertTrue(self.token.is_used)
    
    def test_str_representation(self):
        """Test string representation."""
        self.assertEqual(str(self.token), 'test@example.com - 123456')
    
    def test_one_token_per_user(self):
        """Test only one token per user (OneToOne)."""
        new_token = EmailVerificationToken(
            user=self.user,
            token='654321',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        # This should work because OneToOne allows replace
        new_token.save()
        # Verify only one token exists
        self.assertEqual(
            EmailVerificationToken.objects.filter(user=self.user).count(),
            1
        )


class PasswordResetTokenModelTest(TestCase):
    """Test PasswordResetToken model."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!'
        )
        self.token = PasswordResetToken.objects.create(
            user=self.user,
            token='654321',
            expires_at=timezone.now() + timedelta(hours=1)
        )
    
    def test_is_valid_when_not_expired(self):
        """Test token is valid when not expired."""
        self.assertTrue(self.token.is_valid())
    
    def test_is_invalid_when_expired(self):
        """Test token is invalid when expired."""
        self.token.expires_at = timezone.now() - timedelta(minutes=1)
        self.token.save()
        self.assertFalse(self.token.is_valid())
    
    def test_is_invalid_when_used(self):
        """Test token is invalid when used."""
        self.token.is_used = True
        self.token.save()
        self.assertFalse(self.token.is_valid())
    
    def test_multiple_tokens_per_user(self):
        """Test multiple tokens can exist per user (ForeignKey)."""
        token2 = PasswordResetToken.objects.create(
            user=self.user,
            token='111111',
            expires_at=timezone.now() + timedelta(hours=1)
        )
        self.assertEqual(
            PasswordResetToken.objects.filter(user=self.user).count(),
            2
        )


class LoginAttemptModelTest(TestCase):
    """Test LoginAttempt model."""
    
    def test_create_login_attempt(self):
        """Test creating a login attempt."""
        attempt = LoginAttempt.objects.create(
            email='test@example.com',
            ip_address='192.168.1.1',
            success=True
        )
        self.assertEqual(attempt.email, 'test@example.com')
        self.assertTrue(attempt.success)
    
    def test_failed_login_attempt(self):
        """Test recording failed login."""
        attempt = LoginAttempt.objects.create(
            email='test@example.com',
            ip_address='192.168.1.1',
            success=False,
            error_message='Invalid password'
        )
        self.assertFalse(attempt.success)
        self.assertEqual(attempt.error_message, 'Invalid password')


class RegisterViewTest(APITestCase):
    """Test user registration."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.register_data = {
            'email': 'newuser@example.com',
            'username': 'newuser',
            'password': 'NewPass123!',
            'password_confirm': 'NewPass123!',
            'first_name': 'New',
            'last_name': 'User',
        }
    
    def test_register_success(self):
        """Test successful registration."""
        response = self.client.post('/api/v1/auth/register/', self.register_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], 'newuser@example.com')
        self.assertFalse(response.data['user']['is_email_verified'])

        # No token while verification is required - it would bypass the gate
        self.assertNotIn('token', response.data)

        # User should be created
        user = User.objects.get(email='newuser@example.com')
        self.assertEqual(user.username, 'newuser')

        # Token row still exists (created by the post_save signal)
        self.assertTrue(Token.objects.filter(user=user).exists())

    @override_settings(REQUIRE_EMAIL_VERIFICATION=False)
    def test_register_returns_token_when_verification_not_required(self):
        """Test registration hands back a token when the gate is off."""
        response = self.client.post('/api/v1/auth/register/', self.register_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('token', response.data)

        user = User.objects.get(email='newuser@example.com')
        token = Token.objects.get(user=user)
        self.assertEqual(token.key, response.data['token'])

    def _existing_user_kwargs(self):
        """register_data minus the API-only confirmation field."""
        return {k: v for k, v in self.register_data.items() if k != 'password_confirm'}
    
    def test_register_email_already_exists(self):
        """Test registration with existing email."""
        User.objects.create_user(**self._existing_user_kwargs())
        
        response = self.client.post('/api/v1/auth/register/', self.register_data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)
    
    def test_register_username_already_exists(self):
        """Test registration with existing username."""
        User.objects.create_user(**self._existing_user_kwargs())
        
        data = self.register_data.copy()
        data['email'] = 'another@example.com'
        response = self.client.post('/api/v1/auth/register/', data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)
    
    def test_register_passwords_dont_match(self):
        """Test registration with mismatched passwords."""
        data = self.register_data.copy()
        data['password_confirm'] = 'DifferentPass123!'
        
        response = self.client.post('/api/v1/auth/register/', data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_register_short_password(self):
        """Test registration with short password."""
        data = self.register_data.copy()
        data['password'] = 'short'
        data['password_confirm'] = 'short'
        
        response = self.client.post('/api/v1/auth/register/', data)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_verification_email_created(self):
        """Test that verification token is created on registration."""
        self.client.post('/api/v1/auth/register/', self.register_data)
        
        user = User.objects.get(email='newuser@example.com')
        token = EmailVerificationToken.objects.get(user=user)
        
        self.assertTrue(token.token.isdigit())
        self.assertEqual(len(token.token), 6)


class LoginViewTest(APITestCase):
    """Test user login."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!',
            is_email_verified=True,
        )

    def test_login_success(self):
        """Test successful login."""
        response = self.client.post('/api/v1/auth/login/', {
            'email': 'test@example.com',
            'password': 'TestPass123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['user']['email'], 'test@example.com')
    
    def test_login_invalid_email(self):
        """Test login with invalid email."""
        response = self.client.post('/api/v1/auth/login/', {
            'email': 'nonexistent@example.com',
            'password': 'TestPass123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_login_invalid_password(self):
        """Test login with invalid password."""
        response = self.client.post('/api/v1/auth/login/', {
            'email': 'test@example.com',
            'password': 'WrongPassword123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_login_updates_last_login(self):
        """Test that login updates last_login timestamp."""
        old_last_login = self.user.last_login
        
        self.client.post('/api/v1/auth/login/', {
            'email': 'test@example.com',
            'password': 'TestPass123!'
        })
        
        self.user.refresh_from_db()
        self.assertNotEqual(self.user.last_login, old_last_login)

    def test_login_blocked_when_email_not_verified(self):
        """Test login is refused for an unverified email."""
        User.objects.create_user(
            email='unverified@example.com',
            username='unverified',
            password='TestPass123!'
        )

        response = self.client.post('/api/v1/auth/login/', {
            'email': 'unverified@example.com',
            'password': 'TestPass123!'
        })

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['code'], 'email_not_verified')
        self.assertNotIn('token', response.data)

    @override_settings(REQUIRE_EMAIL_VERIFICATION=False)
    def test_login_allowed_when_verification_not_required(self):
        """Test an unverified user can log in when the gate is off."""
        User.objects.create_user(
            email='unverified@example.com',
            username='unverified',
            password='TestPass123!'
        )

        response = self.client.post('/api/v1/auth/login/', {
            'email': 'unverified@example.com',
            'password': 'TestPass123!'
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)


class VerifyEmailViewTest(APITestCase):
    """Test email verification with code."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!'
        )
        self.email_token = EmailVerificationToken.objects.create(
            user=self.user,
            token='123456',
            expires_at=timezone.now() + timedelta(hours=24)
        )
    
    def test_verify_email_success(self):
        """Test successful email verification with code."""
        self.assertFalse(self.user.is_email_verified)
        
        response = self.client.post('/api/v1/auth/verify-email/', {
            'email': 'test@example.com',
            'code': '123456'
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)
        
        self.email_token.refresh_from_db()
        self.assertTrue(self.email_token.is_used)
    
    def test_verify_email_invalid_code(self):
        """Test verification with invalid code."""
        response = self.client.post('/api/v1/auth/verify-email/', {
            'email': 'test@example.com',
            'code': '000000'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_verify_email_code_too_short(self):
        """Test verification with code that's too short."""
        response = self.client.post('/api/v1/auth/verify-email/', {
            'email': 'test@example.com',
            'code': '12345'  # Only 5 digits
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_verify_email_non_numeric_code(self):
        """Test verification with non-numeric code."""
        response = self.client.post('/api/v1/auth/verify-email/', {
            'email': 'test@example.com',
            'code': 'abcdef'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_verify_email_already_used(self):
        """Test verification with already-used code."""
        self.email_token.mark_used()
        
        response = self.client.post('/api/v1/auth/verify-email/', {
            'email': 'test@example.com',
            'code': '123456'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_verify_email_expired_code(self):
        """Test verification with expired code."""
        self.email_token.expires_at = timezone.now() - timedelta(hours=1)
        self.email_token.save()
        
        response = self.client.post('/api/v1/auth/verify-email/', {
            'email': 'test@example.com',
            'code': '123456'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ResendVerificationEmailViewTest(APITestCase):
    """Test resending verification email."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!'
        )
    
    def test_resend_verification_email(self):
        """Test resending verification email."""
        old_token = EmailVerificationToken.objects.get(user=self.user)
        old_code = old_token.token
        
        response = self.client.post('/api/v1/auth/resend-verification/', {
            'email': 'test@example.com'
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # New token should be created
        new_token = EmailVerificationToken.objects.get(user=self.user)
        self.assertNotEqual(new_token.token, old_code)
    
    def test_resend_verification_email_not_found(self):
        """Test resending to non-existent email."""
        response = self.client.post('/api/v1/auth/resend-verification/', {
            'email': 'nonexistent@example.com'
        })
        
        # Should still return 200 for security (don't reveal if email exists)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_resend_verification_already_verified(self):
        """Test resending for already-verified email."""
        self.user.is_email_verified = True
        self.user.save()
        
        response = self.client.post('/api/v1/auth/resend-verification/', {
            'email': 'test@example.com'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class ForgotPasswordViewTest(APITestCase):
    """Test password reset request."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!'
        )
    
    def test_forgot_password_success(self):
        """Test successful password reset request."""
        response = self.client.post('/api/v1/auth/forgot-password/', {
            'email': 'test@example.com'
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Reset token should be created
        reset_token = PasswordResetToken.objects.get(user=self.user)
        self.assertTrue(reset_token.token.isdigit())
        self.assertEqual(len(reset_token.token), 6)
    
    def test_forgot_password_nonexistent_email(self):
        """Test forgot password with non-existent email."""
        response = self.client.post('/api/v1/auth/forgot-password/', {
            'email': 'nonexistent@example.com'
        })
        
        # Should return 200 for security (don't reveal if email exists)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class ResetPasswordViewTest(APITestCase):
    """Test password reset with code."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!'
        )
        self.reset_token = PasswordResetToken.objects.create(
            user=self.user,
            token='654321',
            expires_at=timezone.now() + timedelta(hours=1)
        )
    
    def test_reset_password_success(self):
        """Test successful password reset."""
        old_password = self.user.password
        
        response = self.client.post('/api/v1/auth/reset-password/', {
            'email': 'test@example.com',
            'code': '654321',
            'new_password': 'NewPass123!',
            'new_password_confirm': 'NewPass123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.user.refresh_from_db()
        self.assertNotEqual(self.user.password, old_password)
        self.assertTrue(self.user.check_password('NewPass123!'))
        
        self.reset_token.refresh_from_db()
        self.assertTrue(self.reset_token.is_used)
    
    def test_reset_password_invalid_code(self):
        """Test reset with invalid code."""
        response = self.client.post('/api/v1/auth/reset-password/', {
            'email': 'test@example.com',
            'code': '000000',
            'new_password': 'NewPass123!',
            'new_password_confirm': 'NewPass123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_reset_password_passwords_dont_match(self):
        """Test reset with mismatched passwords."""
        response = self.client.post('/api/v1/auth/reset-password/', {
            'email': 'test@example.com',
            'code': '654321',
            'new_password': 'NewPass123!',
            'new_password_confirm': 'DifferentPass123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_reset_password_expired_code(self):
        """Test reset with expired code."""
        self.reset_token.expires_at = timezone.now() - timedelta(minutes=1)
        self.reset_token.save()
        
        response = self.client.post('/api/v1/auth/reset-password/', {
            'email': 'test@example.com',
            'code': '654321',
            'new_password': 'NewPass123!',
            'new_password_confirm': 'NewPass123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class CurrentUserViewTest(APITestCase):
    """Test getting and updating current user."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!',
            first_name='Test',
            last_name='User'
        )
        self.token = Token.objects.get(user=self.user)
    
    def test_get_current_user_authenticated(self):
        """Test getting current user when authenticated."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get('/api/v1/auth/me/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'test@example.com')
        self.assertEqual(response.data['full_name'], 'Test User')
    
    def test_get_current_user_not_authenticated(self):
        """Test getting current user when not authenticated."""
        response = self.client.get('/api/v1/auth/me/')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_update_current_user(self):
        """Test updating current user info."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        response = self.client.put('/api/v1/auth/me/', {
            'first_name': 'Updated',
            'phone': '+234123456789'
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.phone, '+234123456789')


class LogoutViewTest(APITestCase):
    """Test user logout."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!'
        )
        self.token = Token.objects.get(user=self.user)
    
    def test_logout_success(self):
        """Test successful logout."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        response = self.client.post('/api/v1/auth/logout/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        # Token should be deleted
        self.assertFalse(Token.objects.filter(user=self.user).exists())
    
    def test_logout_not_authenticated(self):
        """Test logout when not authenticated."""
        response = self.client.post('/api/v1/auth/logout/')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_cannot_use_deleted_token(self):
        """Test that deleted token cannot be used."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        self.client.post('/api/v1/auth/logout/')
        
        # Try to use the deleted token
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get('/api/v1/auth/me/')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ChangePasswordViewTest(APITestCase):
    """Test changing password for authenticated user."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!'
        )
        self.token = Token.objects.get(user=self.user)
    
    def test_change_password_success(self):
        """Test successful password change."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        response = self.client.post('/api/v1/auth/change-password/', {
            'old_password': 'TestPass123!',
            'new_password': 'NewPass123!',
            'new_password_confirm': 'NewPass123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('NewPass123!'))
    
    def test_change_password_invalid_old_password(self):
        """Test password change with wrong old password."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        response = self.client.post('/api/v1/auth/change-password/', {
            'old_password': 'WrongPass123!',
            'new_password': 'NewPass123!',
            'new_password_confirm': 'NewPass123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_change_password_passwords_dont_match(self):
        """Test password change with mismatched new passwords."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        
        response = self.client.post('/api/v1/auth/change-password/', {
            'old_password': 'TestPass123!',
            'new_password': 'NewPass123!',
            'new_password_confirm': 'DifferentPass123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_change_password_not_authenticated(self):
        """Test password change when not authenticated."""
        response = self.client.post('/api/v1/auth/change-password/', {
            'old_password': 'TestPass123!',
            'new_password': 'NewPass123!',
            'new_password_confirm': 'NewPass123!'
        })
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class AuthServiceTest(TestCase):
    """Test AuthService business logic."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.user_data = {
            'email': 'test@example.com',
            'username': 'testuser',
            'password': 'TestPass123!',
        }
    
    def test_create_user_via_service(self):
        """Test creating user via AuthService."""
        user = AuthService.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!'
        )
        
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'test@example.com')
        
        # Verification email should be sent (check token created)
        token = EmailVerificationToken.objects.get(user=user)
        self.assertIsNotNone(token)
    
    def test_authenticate_user_success(self):
        """Test authenticating user via AuthService."""
        User.objects.create_user(**self.user_data)
        
        user = AuthService.authenticate_user(
            email='test@example.com',
            password='TestPass123!'
        )
        
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'test@example.com')
    
    def test_authenticate_user_invalid_password(self):
        """Test authenticating with invalid password."""
        User.objects.create_user(**self.user_data)
        
        user = AuthService.authenticate_user(
            email='test@example.com',
            password='WrongPassword'
        )
        
        self.assertIsNone(user)
    
    def test_authenticate_user_not_found(self):
        """Test authenticating non-existent user."""
        user = AuthService.authenticate_user(
            email='nonexistent@example.com',
            password='TestPass123!'
        )
        
        self.assertIsNone(user)
    
    def test_verify_email_success(self):
        """Test email verification via AuthService."""
        user = User.objects.create_user(**self.user_data)
        email_token = EmailVerificationToken.objects.get(user=user)
        code = email_token.token
        
        verified_user, error = AuthService.verify_email(user.email, code)
        
        self.assertIsNotNone(verified_user)
        self.assertIsNone(error)
        
        verified_user.refresh_from_db()
        self.assertTrue(verified_user.is_email_verified)
    
    def test_verify_email_invalid_code(self):
        """Test email verification with invalid code."""
        user = User.objects.create_user(**self.user_data)

        verified_user, error = AuthService.verify_email(user.email, '000000')
        
        self.assertIsNone(verified_user)
        self.assertIsNotNone(error)
    
    def test_reset_password_success(self):
        """Test password reset via AuthService."""
        user = User.objects.create_user(**self.user_data)
        reset_token = PasswordResetToken.objects.create(
            user=user,
            token='654321',
            expires_at=timezone.now() + timedelta(hours=1)
        )
        
        reset_user, error = AuthService.reset_password(user.email, '654321', 'NewPass123!')
        
        self.assertIsNotNone(reset_user)
        self.assertIsNone(error)
        
        reset_user.refresh_from_db()
        self.assertTrue(reset_user.check_password('NewPass123!'))
    
    def test_change_password_success(self):
        """Test changing password via AuthService."""
        user = User.objects.create_user(**self.user_data)
        
        success, error = AuthService.change_password(
            user=user,
            old_password='TestPass123!',
            new_password='NewPass123!'
        )
        
        self.assertTrue(success)
        self.assertIsNone(error)
        
        user.refresh_from_db()
        self.assertTrue(user.check_password('NewPass123!'))
    
    def test_change_password_invalid_old_password(self):
        """Test changing password with wrong old password."""
        user = User.objects.create_user(**self.user_data)
        
        success, error = AuthService.change_password(
            user=user,
            old_password='WrongPassword',
            new_password='NewPass123!'
        )
        
        self.assertFalse(success)
        self.assertIsNotNone(error)
    
    def test_get_or_create_token(self):
        """Test getting or creating token via AuthService."""
        user = User.objects.create_user(**self.user_data)
        
        token1 = AuthService.get_or_create_token(user)
        token2 = AuthService.get_or_create_token(user)
        
        # Should return the same token
        self.assertEqual(token1.key, token2.key)
    
    def test_revoke_token(self):
        """Test revoking token via AuthService."""
        user = User.objects.create_user(**self.user_data)
        token = Token.objects.get(user=user)
        
        AuthService.revoke_token(user)
        
        self.assertFalse(Token.objects.filter(user=user).exists())


class IntegrationTest(APITestCase):
    """Integration tests for complete auth flow."""
    
    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
    
    def test_complete_registration_and_verification_flow(self):
        """Test complete flow: register -> verify email -> login -> access user"""
        
        # 1. Register
        register_response = self.client.post('/api/v1/auth/register/', {
            'email': 'newuser@example.com',
            'username': 'newuser',
            'password': 'NewPass123!',
            'password_confirm': 'NewPass123!',
            'first_name': 'New',
            'last_name': 'User'
        })
        self.assertEqual(register_response.status_code, status.HTTP_201_CREATED)

        # 2. Get verification code
        user = User.objects.get(email='newuser@example.com')
        email_token = EmailVerificationToken.objects.get(user=user)
        code = email_token.token
        
        # 3. Verify email
        verify_response = self.client.post('/api/v1/auth/verify-email/', {
            'email': 'newuser@example.com',
            'code': code
        })
        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        
        # 4. Login
        login_response = self.client.post('/api/v1/auth/login/', {
            'email': 'newuser@example.com',
            'password': 'NewPass123!'
        })
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        login_token = login_response.data['token']
        
        # 5. Access protected endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {login_token}')
        me_response = self.client.get('/api/v1/auth/me/')
        
        self.assertEqual(me_response.status_code, status.HTTP_200_OK)
        self.assertTrue(me_response.data['is_email_verified'])
    
    def test_complete_password_reset_flow(self):
        """Test complete password reset flow."""
        
        # 1. Create user (verified, so step 5 can log in)
        user = User.objects.create_user(
            email='test@example.com',
            username='testuser',
            password='TestPass123!',
            is_email_verified=True,
        )

        # 2. Request password reset
        forgot_response = self.client.post('/api/v1/auth/forgot-password/', {
            'email': 'test@example.com'
        })
        self.assertEqual(forgot_response.status_code, status.HTTP_200_OK)
        
        # 3. Get reset code
        reset_token = PasswordResetToken.objects.get(user=user)
        code = reset_token.token
        
        # 4. Reset password
        reset_response = self.client.post('/api/v1/auth/reset-password/', {
            'email': 'test@example.com',
            'code': code,
            'new_password': 'NewPass123!',
            'new_password_confirm': 'NewPass123!'
        })
        self.assertEqual(reset_response.status_code, status.HTTP_200_OK)
        
        # 5. Login with new password
        login_response = self.client.post('/api/v1/auth/login/', {
            'email': 'test@example.com',
            'password': 'NewPass123!'
        })
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)


class EmailRollbackTest(APITestCase):
    """A failed send must leave no trace of the writes it accompanied."""

    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.register_data = {
            'email': 'rollback@example.com',
            'username': 'rollbackuser',
            'password': 'TestPass123!',
            'password_confirm': 'TestPass123!',
        }

    @staticmethod
    def smtp_down():
        """Patch send_mail where services.py bound it, not where it's defined."""
        return patch(
            'apps.authentication.services.send_mail',
            side_effect=SMTPException('connection refused'),
        )

    def test_register_rolls_back_everything(self):
        """No verification email means no user, no auth token, no code."""
        with self.smtp_down():
            response = self.client.post('/api/v1/auth/register/', self.register_data)

        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertEqual(
            User.objects.filter(email='rollback@example.com').count(), 0
        )
        self.assertEqual(Token.objects.count(), 0)
        self.assertEqual(EmailVerificationToken.objects.count(), 0)

    def test_register_can_be_retried_after_failure(self):
        """The rolled-back email is free again, so validate_email won't block it."""
        with self.smtp_down():
            self.client.post('/api/v1/auth/register/', self.register_data)

        retry = self.client.post('/api/v1/auth/register/', self.register_data)

        self.assertEqual(retry.status_code, status.HTTP_201_CREATED)
        self.assertEqual(
            User.objects.filter(email='rollback@example.com').count(), 1
        )

    def test_resend_verification_preserves_existing_code(self):
        """A failed resend must not destroy the code the user already holds."""
        user = User.objects.create_user(
            email='resend@example.com',
            username='resenduser',
            password='TestPass123!',
        )
        EmailVerificationToken.objects.create(
            user=user,
            token='111111',
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        with self.smtp_down():
            response = self.client.post(
                '/api/v1/auth/resend-verification/', {'email': 'resend@example.com'}
            )

        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        token = EmailVerificationToken.objects.get(user=user)
        self.assertEqual(token.token, '111111')
        self.assertTrue(token.is_valid())

    def test_forgot_password_preserves_existing_code(self):
        """Same for the reset code: a failed send must not wipe the old one."""
        user = User.objects.create_user(
            email='forgot@example.com',
            username='forgotuser',
            password='TestPass123!',
        )
        PasswordResetToken.objects.create(
            user=user,
            token='222222',
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        with self.smtp_down():
            response = self.client.post(
                '/api/v1/auth/forgot-password/', {'email': 'forgot@example.com'}
            )

        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)
        self.assertEqual(PasswordResetToken.objects.filter(user=user).count(), 1)
        self.assertEqual(PasswordResetToken.objects.get(user=user).token, '222222')

    def test_working_email_still_registers(self):
        """The happy path is untouched by the rollback wrapper."""
        response = self.client.post('/api/v1/auth/register/', self.register_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(email='rollback@example.com')
        self.assertTrue(EmailVerificationToken.objects.filter(user=user).exists())
        self.assertEqual(len(mail.outbox), 1)


class MultiWriteRollbackTest(APITestCase):
    """Flows that write several rows must not commit half of them.

    Each test breaks the *last* write in the sequence and checks the earlier
    ones were undone.
    """

    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='multi@example.com',
            username='multiuser',
            password='OldPass123!',
        )

    def test_reset_password_rolls_back_when_revoke_fails(self):
        """Password must not change if sessions can't be revoked."""
        reset_token = PasswordResetToken.objects.create(
            user=self.user,
            token='333333',
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        with patch.object(
            AuthService, 'revoke_token', side_effect=RuntimeError('db gone')
        ):
            with self.assertRaises(RuntimeError):
                AuthService.reset_password(
                    email=self.user.email, code='333333', new_password='NewPass123!',
                )

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('OldPass123!'))
        reset_token.refresh_from_db()
        self.assertFalse(reset_token.is_used)

    def test_change_password_rolls_back_when_revoke_fails(self):
        """A changed password with live stolen sessions is the failure to avoid."""
        with patch.object(
            AuthService, 'revoke_token', side_effect=RuntimeError('db gone')
        ):
            with self.assertRaises(RuntimeError):
                AuthService.change_password(
                    user=self.user,
                    old_password='OldPass123!',
                    new_password='NewPass123!',
                )

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('OldPass123!'))

    def test_verify_email_rolls_back_when_marking_code_used_fails(self):
        """Don't verify the user while leaving the code replayable."""
        EmailVerificationToken.objects.create(
            user=self.user,
            token='444444',
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        with patch.object(
            EmailVerificationToken, 'mark_used', side_effect=RuntimeError('db gone')
        ):
            with self.assertRaises(RuntimeError):
                AuthService.verify_email(self.user.email, '444444')

        self.user.refresh_from_db()
        self.assertFalse(self.user.is_email_verified)


# Run with: python manage.py test apps.authentication.tests

class LoginAttemptAuditTest(APITestCase):
    """Every login attempt should leave exactly one audit row."""

    def setUp(self):
        # Throttle state is cached and LocMemCache outlives a single test.
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='audit@example.com',
            username='audituser',
            password='TestPass123!',
            is_email_verified=True,
        )

    def test_successful_login_is_recorded(self):
        response = self.client.post(
            '/api/v1/auth/login/',
            {'email': 'audit@example.com', 'password': 'TestPass123!'},
            HTTP_USER_AGENT='pytest-agent/1.0',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        attempt = LoginAttempt.objects.get()
        self.assertEqual(attempt.email, 'audit@example.com')
        self.assertTrue(attempt.success)
        self.assertEqual(attempt.device_info, 'pytest-agent/1.0')
        self.assertEqual(attempt.error_message, '')
        self.assertEqual(attempt.ip_address, '127.0.0.1')

    def test_bad_password_is_recorded_as_failure(self):
        response = self.client.post(
            '/api/v1/auth/login/',
            {'email': 'audit@example.com', 'password': 'WrongPassword123!'},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        attempt = LoginAttempt.objects.get()
        self.assertFalse(attempt.success)
        self.assertEqual(attempt.error_message, 'Invalid email or password')

    def test_unknown_email_is_recorded(self):
        self.client.post(
            '/api/v1/auth/login/',
            {'email': 'nobody@example.com', 'password': 'TestPass123!'},
        )
        attempt = LoginAttempt.objects.get()
        self.assertEqual(attempt.email, 'nobody@example.com')
        self.assertFalse(attempt.success)

    def test_unverified_login_is_recorded_with_its_own_reason(self):
        """A correct password blocked by the gate must be distinguishable."""
        self.user.is_email_verified = False
        self.user.save(update_fields=['is_email_verified'])

        response = self.client.post(
            '/api/v1/auth/login/',
            {'email': 'audit@example.com', 'password': 'TestPass123!'},
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        attempt = LoginAttempt.objects.get()
        self.assertFalse(attempt.success)
        self.assertEqual(attempt.error_message, 'Email not verified')

    def test_long_user_agent_is_truncated_not_dropped(self):
        self.client.post(
            '/api/v1/auth/login/',
            {'email': 'audit@example.com', 'password': 'TestPass123!'},
            HTTP_USER_AGENT='x' * 600,
        )
        self.assertEqual(len(LoginAttempt.objects.get().device_info), 255)

    def test_forwarded_header_ignored_unless_proxy_is_trusted(self):
        """A client-supplied X-Forwarded-For must not reach the audit row."""
        self.client.post(
            '/api/v1/auth/login/',
            {'email': 'audit@example.com', 'password': 'TestPass123!'},
            HTTP_X_FORWARDED_FOR='203.0.113.7',
        )
        self.assertEqual(LoginAttempt.objects.get().ip_address, '127.0.0.1')

    @override_settings(TRUSTED_PROXY_HEADER=True)
    def test_forwarded_header_used_when_proxy_is_trusted(self):
        self.client.post(
            '/api/v1/auth/login/',
            {'email': 'audit@example.com', 'password': 'TestPass123!'},
            HTTP_X_FORWARDED_FOR='203.0.113.7, 10.0.0.1',
        )
        self.assertEqual(LoginAttempt.objects.get().ip_address, '203.0.113.7')


class PasswordPolicyTest(APITestCase):
    """AUTH_PASSWORD_VALIDATORS must apply over the API, not just in the admin."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()

    def test_register_rejects_common_password(self):
        response = self.client.post('/api/v1/auth/register/', {
            'email': 'weak@example.com',
            'username': 'weakuser',
            'password': 'password123',
            'password_confirm': 'password123',
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(email='weak@example.com').exists())

    def test_register_rejects_all_numeric_password(self):
        response = self.client.post('/api/v1/auth/register/', {
            'email': 'weak@example.com',
            'username': 'weakuser',
            'password': '84927104',
            'password_confirm': '84927104',
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_rejects_password_similar_to_username(self):
        """The similarity validator needs the unsaved user to do anything."""
        response = self.client.post('/api/v1/auth/register/', {
            'email': 'adalovelace@example.com',
            'username': 'adalovelace',
            'password': 'adalovelace1',
            'password_confirm': 'adalovelace1',
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_rejects_weak_password(self):
        user = User.objects.create_user(
            email='pol@example.com', username='poluser',
            password='TestPass123!', is_email_verified=True,
        )
        self.client.force_authenticate(user=user)

        response = self.client.post('/api/v1/auth/change-password/', {
            'old_password': 'TestPass123!',
            'new_password': 'password123',
            'new_password_confirm': 'password123',
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user.refresh_from_db()
        self.assertTrue(user.check_password('TestPass123!'))

    def test_reset_password_rejects_weak_password(self):
        user = User.objects.create_user(
            email='pol@example.com', username='poluser', password='TestPass123!',
        )
        PasswordResetToken.objects.create(
            user=user, token='654321',
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        response = self.client.post('/api/v1/auth/reset-password/', {
            'email': 'pol@example.com',
            'code': '654321',
            'new_password': 'password123',
            'new_password_confirm': 'password123',
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        user.refresh_from_db()
        self.assertTrue(user.check_password('TestPass123!'))
        # The code survives a rejected attempt, so the user can try again.
        self.assertTrue(PasswordResetToken.objects.get(user=user).is_valid())


class CodeScopingTest(APITestCase):
    """A code must only work for the account it was issued to."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.alice = User.objects.create_user(
            email='alice@example.com', username='alice', password='TestPass123!',
        )
        self.bob = User.objects.create_user(
            email='bob@example.com', username='bob', password='TestPass123!',
        )

    def test_verification_code_does_not_work_for_another_account(self):
        alice_code = EmailVerificationToken.objects.get(user=self.alice).token

        response = self.client.post('/api/v1/auth/verify-email/', {
            'email': 'bob@example.com',
            'code': alice_code,
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Invalid verification code.')

        # Neither account is touched by the failed attempt.
        self.alice.refresh_from_db()
        self.bob.refresh_from_db()
        self.assertFalse(self.alice.is_email_verified)
        self.assertFalse(self.bob.is_email_verified)
        self.assertFalse(EmailVerificationToken.objects.get(user=self.alice).is_used)

    def test_reset_code_does_not_work_for_another_account(self):
        PasswordResetToken.objects.create(
            user=self.alice, token='654321',
            expires_at=timezone.now() + timedelta(minutes=10),
        )

        response = self.client.post('/api/v1/auth/reset-password/', {
            'email': 'bob@example.com',
            'code': '654321',
            'new_password': 'BobNewPass123!',
            'new_password_confirm': 'BobNewPass123!',
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.bob.refresh_from_db()
        self.assertTrue(self.bob.check_password('TestPass123!'))

    def test_email_scope_is_case_insensitive(self):
        code = EmailVerificationToken.objects.get(user=self.alice).token

        response = self.client.post('/api/v1/auth/verify-email/', {
            'email': 'ALICE@Example.com',
            'code': code,
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_email_is_required(self):
        code = EmailVerificationToken.objects.get(user=self.alice).token
        response = self.client.post('/api/v1/auth/verify-email/', {'code': code})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)


class ThrottleTest(APITestCase):
    """The code-entry endpoints must not be walkable."""

    def setUp(self):
        cache.clear()
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='throttle@example.com', username='throttleuser',
            password='TestPass123!', is_email_verified=True,
        )

    def test_code_entry_is_throttled(self):
        # THROTTLE_RATES is a class attribute bound at import time, so
        # override_settings(REST_FRAMEWORK=...) never reaches it - patch the
        # dict the throttle actually reads.
        with patch.dict(ScopedRateThrottle.THROTTLE_RATES, {'auth_code_entry': '3/hour'}):
            self._exhaust_code_entry()

    def _exhaust_code_entry(self):
        for _ in range(3):
            response = self.client.post('/api/v1/auth/verify-email/', {
                'email': 'throttle@example.com', 'code': '000000',
            })
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.post('/api/v1/auth/verify-email/', {
            'email': 'throttle@example.com', 'code': '000000',
        })
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_login_is_throttled(self):
        with patch.dict(ScopedRateThrottle.THROTTLE_RATES, {'auth_login': '2/hour'}):
            self._exhaust_login()

    def _exhaust_login(self):
        for _ in range(2):
            self.client.post('/api/v1/auth/login/', {
                'email': 'throttle@example.com', 'password': 'WrongPassword123!',
            })

        response = self.client.post('/api/v1/auth/login/', {
            'email': 'throttle@example.com', 'password': 'TestPass123!',
        })
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_authenticated_endpoints_are_not_throttled(self):
        """ScopedRateThrottle must leave scope-less views alone."""
        self.client.force_authenticate(user=self.user)
        for _ in range(30):
            response = self.client.get('/api/v1/auth/me/')
            self.assertEqual(response.status_code, status.HTTP_200_OK)
