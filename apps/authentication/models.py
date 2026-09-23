# auth/models.py
import uuid
from django.db import models
from django.utils import timezone
from apps.user.models import User


class EmailVerificationToken(models.Model):
    """6-digit code for email verification (not a link)."""
    
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE,
        related_name='email_token'
    )
    token = models.CharField(max_length=100)  # Stores "123456"
    token_uuid = models.UUIDField(default=uuid.uuid4, unique=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'email_verification_tokens'
        verbose_name = 'Email Verification Token'
        verbose_name_plural = 'Email Verification Tokens'
        ordering = ['-created_at']
    
    def __str__(self):
        return f'{self.user.email} - {self.token}'
    
    def save(self, *args, **kwargs):
        """Issuing a new code replaces any existing one for the user."""
        if self._state.adding:
            EmailVerificationToken.objects.filter(user=self.user).delete()
        super().save(*args, **kwargs)
    
    def is_valid(self):
        """Check if token is still valid (not expired and not used)."""
        now = timezone.now()
        return not self.is_used and now < self.expires_at
    
    def mark_used(self):
        """Mark token as used."""
        self.is_used = True
        self.save()


class PasswordResetToken(models.Model):
    """6-digit code for password reset (not a link)."""
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='password_reset_tokens'
    )
    token = models.CharField(max_length=100)  # Stores "654321"
    token_uuid = models.UUIDField(default=uuid.uuid4, unique=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'password_reset_tokens'
        verbose_name = 'Password Reset Token'
        verbose_name_plural = 'Password Reset Tokens'
        ordering = ['-created_at']
    
    def __str__(self):
        return f'{self.user.email} - {self.token}'
    
    def is_valid(self):
        """Check if token is still valid (not expired and not used)."""
        now = timezone.now()
        return not self.is_used and now < self.expires_at
    
    def mark_used(self):
        """Mark token as used."""
        self.is_used = True
        self.save()


class LoginAttempt(models.Model):
    """One row per login attempt, successful or not.

    Written by LoginView for every attempt - see AuthService.record_login_attempt.
    `success` is False for anything that did not end in a token, so a correct
    password blocked by the verification gate lands here as a failure with
    `error_message` explaining why.
    """

    email = models.EmailField()
    # Null when the request arrived without a usable REMOTE_ADDR; better an
    # honest unknown than a sentinel address that looks like a real client.
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    success = models.BooleanField()
    device_info = models.CharField(max_length=255, blank=True, null=True)
    error_message = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'login_attempts'
        verbose_name = 'Login Attempt'
        verbose_name_plural = 'Login Attempts'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['email', 'created_at']),
            models.Index(fields=['ip_address', 'created_at']),
        ]
    
    def __str__(self):
        status = 'Success' if self.success else 'Failed'
        return f'{self.email} - {status} - {self.created_at}'