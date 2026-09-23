import logging
import random
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.template.loader import render_to_string
from django.utils import timezone

from rest_framework.authtoken.models import Token

from django.conf import settings

from .exceptions import EmailDeliveryError
from .models import EmailVerificationToken, LoginAttempt, PasswordResetToken

User = get_user_model()

logger = logging.getLogger(__name__)

TOKEN_TTL_MINUTES = 10


class AuthService:

    @staticmethod
    def _send_email(subject, message, html_message, recipient):
        """Send mail, turning any transport failure into EmailDeliveryError.

        Callers run this inside transaction.atomic(), so raising is what rolls the
        accompanying rows back. Anything can come out of an SMTP client - socket
        errors, TLS errors, DNS failures - and they all mean the same thing here.
        """
        try:
            send_mail(
                subject=subject,
                message=message,
                html_message=html_message,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'no-reply@example.com'),
                recipient_list=[recipient],
                fail_silently=False,
            )
        except Exception as exc:
            logger.exception(
                'Email %r to %s failed; rolling back the accompanying writes',
                subject,
                recipient,
            )
            raise EmailDeliveryError() from exc

    @staticmethod
    def _email_context(user, **extra):
        """Context for the HTML email templates.

        The keys here have to match the templates exactly - an unknown name
        renders as an empty string, which is how the code box came out blank.
        """
        return {
            'app_name': settings.APP_NAME,
            'user_name': user.get_full_name() or user.username,
            'expiry_minutes': TOKEN_TTL_MINUTES,
            **extra,
        }

    @staticmethod
    def create_user(email, username, password, first_name='', last_name='', phone=''):
        # The account and its verification email are one unit: if the mail can't
        # go out, the user (plus the rows the post_save signals add) is rolled
        # back so the address stays free to register again.
        with transaction.atomic():
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                phone=phone,
            )
            AuthService.send_verification_email(user)
        return user

    @staticmethod
    def create_email_verification_token(user):
        """Issue a fresh 6-digit code, replacing any previous one."""
        code = str(random.randint(100000, 999999))
        expires_at = timezone.now() + timedelta(minutes=TOKEN_TTL_MINUTES)
        return EmailVerificationToken.objects.create(
            user=user, token=code, expires_at=expires_at
        )

    @staticmethod
    def send_verification_email(user):
        # Issuing a code destroys the user's previous one, so the new code and the
        # email carrying it have to commit together - otherwise a failed send
        # leaves the user with no working code at all.
        with transaction.atomic():
            email_token = AuthService.create_email_verification_token(user)
            code = email_token.token

            context = AuthService._email_context(user, verification_code=code)
            html_message = render_to_string('email_template/email_verification.html', context)
            AuthService._send_email(
                subject='Email Verification',
                message=(
                    f'Hello {user.get_full_name() or user.username},\n\n'
                    f'Your verification code is: {code}\n\n'
                    f'This code will expire in {TOKEN_TTL_MINUTES} minutes.'
                ),
                html_message=html_message,
                recipient=user.email,
            )

        return email_token

    @staticmethod
    def authenticate_user(email, password):
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            return None

        if not user.check_password(password):
            return None

        if not user.is_active:
            return None

        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        return user

    @staticmethod
    def verify_email(email, code):
        # Scoped to the address that asked, not looked up globally: a code is
        # only six digits, so an unscoped lookup means a guess is checked
        # against every live code in the system rather than one account's.
        try:
            token = EmailVerificationToken.objects.get(
                token=code, user__email__iexact=email
            )
        except EmailVerificationToken.DoesNotExist:
            return None, 'Invalid verification code.'

        if not token.is_valid():
            return None, 'Token is invalid or expired.'

        user = token.user

        # Verifying the user and burning the code go together - otherwise a
        # failure between them leaves a verified user holding a replayable code.
        with transaction.atomic():
            user.is_email_verified = True
            user.save(update_fields=['is_email_verified'])
            token.mark_used()

        return user, None

    @staticmethod
    def resend_verification_email(user):
        if user.is_email_verified:
            return None, 'Email is already verified.'
        return AuthService.send_verification_email(user), None

    @staticmethod
    def get_or_create_token(user):
        token, created = Token.objects.get_or_create(user=user)
        return token

    @staticmethod
    def revoke_token(user):
        Token.objects.filter(user=user).delete()
        return True

    @staticmethod
    def send_password_reset_email(user):
        # Same bargain as the verification code: the delete-then-create wipes any
        # code the user already holds, so it only commits if the mail goes out.
        with transaction.atomic():
            PasswordResetToken.objects.filter(user=user).delete()

            code = str(random.randint(100000, 999999))
            expires_at = timezone.now() + timedelta(minutes=TOKEN_TTL_MINUTES)
            reset_token = PasswordResetToken.objects.create(
                user=user, token=code, expires_at=expires_at
            )

            context = AuthService._email_context(user, reset_code=code)
            html_message = render_to_string('email_template/password_reset.html', context)
            AuthService._send_email(
                subject='Password Reset',
                message=(
                    f'Hello {user.get_full_name() or user.username},\n\n'
                    f'Your password reset code is: {code}\n\n'
                    f'This code will expire in {TOKEN_TTL_MINUTES} minutes.'
                ),
                html_message=html_message,
                recipient=user.email,
            )

        return reset_token

    @staticmethod
    def reset_password(email, code, new_password):
        # Scoped by email for the same reason as verify_email.
        try:
            token = PasswordResetToken.objects.get(
                token=code, is_used=False, user__email__iexact=email
            )
        except PasswordResetToken.DoesNotExist:
            return None, 'Invalid reset code.'

        if not token.is_valid():
            return None, 'Token is invalid or expired.'

        user = token.user

        # Run the configured validators here rather than in the serializer:
        # this is the first point where the account is known, and
        # UserAttributeSimilarityValidator needs it to do anything.
        try:
            validate_password(new_password, user=user)
        except DjangoValidationError as exc:
            return None, ' '.join(exc.messages)

        # All three writes are one unit. A partial run either leaves the new
        # password live alongside old sessions, or leaves the reset code valid
        # for a second redemption.
        with transaction.atomic():
            user.set_password(new_password)
            user.save(update_fields=['password'])

            # revoke all tokens so old sessions can't keep using the account
            AuthService.revoke_token(user)

            # Mark reset token as used
            token.mark_used()

        return user, None

    @staticmethod
    def change_password(user, old_password, new_password):
        if not user.check_password(old_password):
            return False, 'Current password is incorrect'

        # A committed password change with the session revocation missing is the
        # exact thing the revoke is here to prevent.
        with transaction.atomic():
            user.set_password(new_password)
            user.save()
            AuthService.revoke_token(user)

        return True, None

    @staticmethod
    def record_login_attempt(email, request, success, error_message=''):
        """Write the audit row for one login attempt.

        Called from the view rather than from authenticate_user, because the
        request - and so the IP and user agent - only exists up there.
        """
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        return LoginAttempt.objects.create(
            email=email[:254],
            ip_address=AuthService.client_ip(request),
            success=success,
            # Both columns are varchar(255); a long user agent is worth keeping
            # truncated rather than losing the whole row to a DataError.
            device_info=user_agent[:255],
            error_message=error_message[:255],
        )

    @staticmethod
    def client_ip(request):
        """Best-effort client IP, or None if the request carries nothing usable.

        X-Forwarded-For is only consulted when a proxy is declared in
        TRUSTED_PROXY_HEADER - a client can set that header itself, so trusting
        it unconditionally would let anyone spread a brute-force across fake
        addresses and defeat the audit trail.
        """
        if getattr(settings, 'TRUSTED_PROXY_HEADER', False):
            forwarded = request.META.get('HTTP_X_FORWARDED_FOR', '')
            if forwarded:
                return forwarded.split(',')[0].strip() or None
        return request.META.get('REMOTE_ADDR') or None

    @staticmethod
    def cleanup_expired_tokens():
        with transaction.atomic():
            email_count, _ = EmailVerificationToken.objects.filter(
                expires_at__lt=timezone.now()
            ).delete()

            password_count, _ = PasswordResetToken.objects.filter(
                expires_at__lt=timezone.now()
            ).delete()

        return {
            'expired_email_tokens': email_count,
            'expired_password_tokens': password_count,
        }
