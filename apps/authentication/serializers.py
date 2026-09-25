from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from .services import AuthService
from apps.user.serializers import UserSerializer
from apps.user.models import User

def validate_password_strength(password, user=None):
    """Run AUTH_PASSWORD_VALIDATORS and re-raise as a DRF error.

    Django's validators raise django.core.exceptions.ValidationError, which DRF
    does not catch - without the translation the failure surfaces as a 500
    instead of a 400. `user` is what UserAttributeSimilarityValidator needs to
    compare against; pass an unsaved instance when the account doesn't exist yet.
    """
    try:
        validate_password(password, user=user)
    except DjangoValidationError as exc:
        raise serializers.ValidationError(list(exc.messages))


class RegisterSerializer(serializers.Serializer):
    """Serialize user registration request."""
    
    email = serializers.EmailField()
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    password_confirm = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    first_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    phone_number = serializers.CharField(max_length=20, required=False, allow_blank=True)
    
    def validate_email(self, value):
        """Validate email is unique."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError('Email already registered')
        return value
    
    def validate_username(self, value):
        """Validate username is unique."""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError('Username already taken')
        return value
    
    def validate(self, data):
        """Validate passwords match and satisfy the configured policy."""
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError('Passwords do not match')

        # The account doesn't exist yet, so hand the validators an unsaved
        # instance - otherwise the similarity check has nothing to compare the
        # password against and silently passes.
        validate_password_strength(
            data['password'],
            user=User(
                email=data.get('email', ''),
                username=data.get('username', ''),
                first_name=data.get('first_name', ''),
                last_name=data.get('last_name', ''),
            ),
        )
        return data
    
    def create(self, validated_data):
        """Create user via AuthService."""
        user = AuthService.create_user(
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            phone_number=validated_data.get('phone_number', ''),
        )
        return user


class LoginSerializer(serializers.Serializer):
    """Serialize user login request."""
    
    email = serializers.EmailField()
    password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    
    def validate(self, data):
        """Authenticate user credentials."""
        user = AuthService.authenticate_user(
            email=data['email'],
            password=data['password']
        )
        if not user:
            raise serializers.ValidationError('Invalid email or password')
        data['user'] = user
        return data


class VerifyEmailSerializer(serializers.Serializer):
    """Serialize email verification request with 6-digit code.

    The email is required so the code can be checked against one account
    instead of every live code in the system.
    """

    email = serializers.EmailField()
    code = serializers.CharField(max_length=6, min_length=6)
    
    def validate_code(self, value):
        """Validate code is 6 digits."""
        if not value.isdigit():
            raise serializers.ValidationError('Code must be 6 digits')
        return value


class ResendVerificationEmailSerializer(serializers.Serializer):
    """Serialize resend verification email request."""
    
    email = serializers.EmailField()
    
    def validate_email(self, value):
        """Reject already-verified emails; stay silent about unknown ones."""
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            return value  # Don't reveal whether the email exists
        
        if user.is_email_verified:
            raise serializers.ValidationError('Email already verified')
        
        return value


class ForgotPasswordSerializer(serializers.Serializer):
    """Serialize forgot password request."""
    
    email = serializers.EmailField()
    
    def validate_email(self, value):
        """Validate email exists (but don't reveal)."""
        # Don't reveal if email exists for security
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            pass  # Silently pass
        return value


class ResetPasswordSerializer(serializers.Serializer):
    """Serialize password reset request with 6-digit code.

    Like VerifyEmailSerializer, the email scopes the code lookup. The password
    policy is enforced in AuthService.reset_password, where the account the code
    belongs to is known.
    """

    email = serializers.EmailField()
    code = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    
    def validate(self, data):
        """Validate passwords match and code is valid."""
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError('Passwords do not match')
        
        # Validate code format
        if not data['code'].isdigit():
            raise serializers.ValidationError('Code must be 6 digits')
        
        return data


class ChangePasswordSerializer(serializers.Serializer):
    """Serialize change password request for authenticated users."""
    
    old_password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    new_password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        min_length=8,
        style={'input_type': 'password'}
    )
    
    def validate(self, data):
        """Validate passwords match and satisfy the configured policy."""
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError('New passwords do not match')

        # The view passes the request in context; the authenticated user is what
        # lets the similarity validator run.
        request = self.context.get('request')
        validate_password_strength(
            data['new_password'],
            user=getattr(request, 'user', None),
        )
        return data


class TokenSerializer(serializers.ModelSerializer):
    """Serialize auth token."""
    
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = Token
        fields = ['key', 'user']


class AuthResponseSerializer(serializers.Serializer):
    """Serialize complete auth response with token and user."""

    token = serializers.CharField()
    user = UserSerializer()


# The serializers below describe response bodies only. The views build these
# dicts by hand, so nothing validates through them - they exist so the OpenAPI
# schema can state what each endpoint actually returns.

class DetailResponseSerializer(serializers.Serializer):
    """A bare `{"detail": "..."}` acknowledgement."""

    detail = serializers.CharField()


class ErrorDetailSerializer(serializers.Serializer):
    """An error body carrying a machine-readable `code` alongside the message.

    Used by the 403 on unverified login (`email_not_verified`) and the 503 when
    an email can't be delivered (`email_delivery_failed`).
    """

    detail = serializers.CharField()
    code = serializers.CharField(required=False)


class RegisterResponseSerializer(serializers.Serializer):
    """Registration result.

    `token` is present only when REQUIRE_EMAIL_VERIFICATION is off - with the
    gate on, handing back a token would route around it.
    """

    user = UserSerializer()
    message = serializers.CharField()
    token = serializers.CharField(required=False)


class VerifyEmailResponseSerializer(serializers.Serializer):
    """Verification result, with the freshly verified user."""

    detail = serializers.CharField()
    user = UserSerializer()