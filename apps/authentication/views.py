# auth/views.py
from rest_framework import views, viewsets, status
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import action
from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from .models import User, EmailVerificationToken
from drf_spectacular.utils import OpenApiResponse, extend_schema
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    VerifyEmailSerializer,
    ResendVerificationEmailSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    ChangePasswordSerializer,
    AuthResponseSerializer,
    DetailResponseSerializer,
    ErrorDetailSerializer,
    RegisterResponseSerializer,
    VerifyEmailResponseSerializer,
)
from .services import AuthService
from apps.user.serializers import UserSerializer


class RegisterView(views.APIView):
    """
    POST /auth/register/
    Register a new user with email and password.
    Sends verification email with 6-digit code.

    The account and the verification email are atomic: if the email can't be
    sent, the user is rolled back and the response is 503, so the address stays
    free to register again.

    When REQUIRE_EMAIL_VERIFICATION is on, no token is returned - otherwise it
    would hand the user a way around the login gate.
    """

    permission_classes = [AllowAny]
    # throttle_scope = 'auth_email_send'

    @extend_schema(
        summary='Register a new account',
        description=(
            'Creates the account and emails a 6-digit verification code. The '
            'two commit together: if the email cannot be sent the user is '
            'rolled back and the response is 503, so the address stays free to '
            'register again and a retry is safe.\n\n'
            'A `token` is included only when REQUIRE_EMAIL_VERIFICATION is off.'
        ),
        tags=['auth'],
        request=RegisterSerializer,
        responses={
            201: RegisterResponseSerializer,
            400: OpenApiResponse(
                description='Validation errors, keyed by field, including password policy.',
            ),
            503: OpenApiResponse(
                response=ErrorDetailSerializer,
                description='Email delivery failed; the account was rolled back.',
            ),
            429: OpenApiResponse(description='Rate limit exceeded.'),
        },
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            response_data = {
                'user': UserSerializer(user).data,
                'message': 'Registration successful. Check your email for verification code.'
            }

            if not settings.REQUIRE_EMAIL_VERIFICATION:
                token, _ = Token.objects.get_or_create(user=user)
                response_data['token'] = token.key

            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(views.APIView):
    """
    POST /auth/login/
    Login with email and password.
    Returns auth token if credentials are valid.

    When REQUIRE_EMAIL_VERIFICATION is on, unverified users get 403.
    """
    
    permission_classes = [AllowAny]
    # throttle_scope = 'auth_login'

    @extend_schema(
        summary='Log in and get a token',
        description=(
            'Exchanges email and password for a DRF auth token.\n\n'
            'With REQUIRE_EMAIL_VERIFICATION on, an unverified account gets 403 '
            'with `code: email_not_verified` even though the credentials were '
            'correct. Bad credentials give 400 with the same message whether '
            'the email exists or not.'
        ),
        tags=['auth'],
        request=LoginSerializer,
        responses={
            200: AuthResponseSerializer,
            400: OpenApiResponse(description='`Invalid email or password`.'),
            403: OpenApiResponse(
                response=ErrorDetailSerializer,
                description='Credentials are valid but the email is unverified.',
            ),
            429: OpenApiResponse(description='Rate limit exceeded.'),
        },
    )
    def post(self, request):
        # Falls back to '' so an attempt with no email at all is still audited.
        email = request.data.get('email') or ''
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data['user']

            # Credentials were correct, so last_login is already stamped by
            # AuthService.authenticate_user even if we block the login here.
            if settings.REQUIRE_EMAIL_VERIFICATION and not user.is_email_verified:
                # Audited as a failure: the credentials were right but no token
                # was issued. error_message is what separates this from a
                # password guess when reading the log back.
                AuthService.record_login_attempt(
                    email, request, success=False, error_message='Email not verified',
                )
                return Response(
                    {
                        'detail': 'Email not verified. Check your inbox for the verification code.',
                        'code': 'email_not_verified',
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            token, _ = Token.objects.get_or_create(user=user)
            AuthService.record_login_attempt(email, request, success=True)

            response_data = {
                'token': token.key,
                'user': UserSerializer(user).data,
            }
            return Response(response_data, status=status.HTTP_200_OK)

        AuthService.record_login_attempt(
            email, request, success=False, error_message='Invalid email or password',
        )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(views.APIView):
    """
    POST /auth/verify-email/
    Verify email using 6-digit code sent via email.
    """
    
    permission_classes = [AllowAny]
    # throttle_scope = 'auth_code_entry'

    @extend_schema(
        summary='Verify an email address',
        description=(
            'Marks the address as verified and burns the code. Codes expire 10 '
            'minutes after they are issued, and requesting a new one replaces '
            'the old.\n\n'
            '`email` is required: the code is only checked against that '
            'account, so a guess cannot match some other user\'s live code.'
        ),
        tags=['auth'],
        request=VerifyEmailSerializer,
        responses={
            200: VerifyEmailResponseSerializer,
            400: OpenApiResponse(
                description=(
                    '`Invalid verification code.` (no such code for that '
                    'address), `Token is invalid or expired.`, or field errors.'
                ),
            ),
            429: OpenApiResponse(description='Rate limit exceeded.'),
        },
    )
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        if serializer.is_valid():
            user, error = AuthService.verify_email(
                email=serializer.validated_data['email'],
                code=serializer.validated_data['code'],
            )
            
            if error:
                return Response({'detail': error}, status=status.HTTP_400_BAD_REQUEST)
            
            response_data = {
                'detail': 'Email verified successfully',
                'user': UserSerializer(user).data,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendVerificationEmailView(views.APIView):
    """
    POST /auth/resend-verification/
    Resend verification email with new 6-digit code.
    """
    
    permission_classes = [AllowAny]
    # throttle_scope = 'auth_email_send'

    @extend_schema(
        summary='Resend the verification code',
        description=(
            'Issues a fresh code and emails it, replacing any code the user '
            'still holds. The response is identical whether or not the address '
            'exists, so it cannot be used to enumerate accounts.\n\n'
            'An already-verified address is the one case that does report back, '
            'as a 400.'
        ),
        tags=['auth'],
        request=ResendVerificationEmailSerializer,
        responses={
            200: DetailResponseSerializer,
            400: OpenApiResponse(description='`Email already verified`, or a malformed address.'),
            503: OpenApiResponse(
                response=ErrorDetailSerializer,
                description='Email delivery failed; the existing code is left intact.',
            ),
            429: OpenApiResponse(description='Rate limit exceeded.'),
        },
    )
    def post(self, request):
        serializer = ResendVerificationEmailSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = User.objects.get(email=email)
                AuthService.send_verification_email(user)
            except User.DoesNotExist:
                pass  # Don't reveal whether the email exists
            
            return Response(
                {'detail': 'Verification email sent'},
                status=status.HTTP_200_OK
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ForgotPasswordView(views.APIView):
    """
    POST /auth/forgot-password/
    Send password reset email with 6-digit code.
    """
    
    permission_classes = [AllowAny]
    # throttle_scope = 'auth_email_send'

    @extend_schema(
        summary='Request a password reset code',
        description=(
            'Emails a 6-digit reset code, valid for 10 minutes. The response is '
            'the same whether or not the address exists.'
        ),
        tags=['auth'],
        request=ForgotPasswordSerializer,
        responses={
            200: DetailResponseSerializer,
            400: OpenApiResponse(description='Malformed email address.'),
            503: OpenApiResponse(
                response=ErrorDetailSerializer,
                description='Email delivery failed; any existing reset code is left intact.',
            ),
            429: OpenApiResponse(description='Rate limit exceeded.'),
        },
    )
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = User.objects.get(email=email)
                AuthService.send_password_reset_email(user)
            except User.DoesNotExist:
                pass  # Don't reveal if email exists
            
            # Always return success for security
            return Response(
                {'detail': 'If email exists, password reset code has been sent'},
                status=status.HTTP_200_OK
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(views.APIView):
    """
    POST /auth/reset-password/
    Reset password using 6-digit code from email.
    """
    
    permission_classes = [AllowAny]
    # throttle_scope = 'auth_code_entry'

    @extend_schema(
        summary='Reset a password with a code',
        description=(
            'Sets the new password, burns the code, and **revokes the account\'s '
            'auth token** - any client holding the old token must log in again.'
            '\n\n`email` scopes the code lookup, and the new password must '
            'satisfy AUTH_PASSWORD_VALIDATORS.'
        ),
        tags=['auth'],
        request=ResetPasswordSerializer,
        responses={
            200: DetailResponseSerializer,
            400: OpenApiResponse(
                description=(
                    '`Invalid reset code.`, `Token is invalid or expired.`, '
                    '`Passwords do not match`, or a password-policy message.'
                ),
            ),
            429: OpenApiResponse(description='Rate limit exceeded.'),
        },
    )
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            user, error = AuthService.reset_password(
                email=serializer.validated_data['email'],
                code=serializer.validated_data['code'],
                new_password=serializer.validated_data['new_password'],
            )
            
            if error:
                return Response({'detail': error}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response(
                {'detail': 'Password reset successfully'},
                status=status.HTTP_200_OK
            )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CurrentUserView(views.APIView):
    """
    GET /auth/me/
    Get current user info (requires token authentication).
    
    PUT /auth/me/
    Update current user info.
    """
    
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary='Get the current user',
        tags=['auth'],
        responses={
            200: UserSerializer,
            401: OpenApiResponse(description='Missing or revoked token.'),
        },
    )
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    @extend_schema(
        summary='Update the current user',
        description=(
            'Served with `partial=True`, so despite the verb every field is '
            'optional and omitted fields are left alone - it behaves as PATCH.\n\n'
            '`id`, `is_email_verified`, `created_at` and `updated_at` are '
            'read-only and ignored if sent.'
        ),
        tags=['auth'],
        request=UserSerializer,
        responses={
            200: UserSerializer,
            400: OpenApiResponse(description='Validation errors, keyed by field.'),
            401: OpenApiResponse(description='Missing or revoked token.'),
        },
    )
    def put(self, request):
        serializer = UserSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(views.APIView):
    """
    POST /auth/logout/
    Logout by deleting auth token (revokes access).
    """
    
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary='Log out',
        description=(
            'Deletes the token row, so the key stops working immediately. A '
            'later login issues a new one.'
        ),
        tags=['auth'],
        request=None,
        responses={
            200: DetailResponseSerializer,
            401: OpenApiResponse(description='Missing or revoked token.'),
        },
    )
    def post(self, request):
        AuthService.revoke_token(request.user)
        return Response(
            {'detail': 'Logout successful'},
            status=status.HTTP_200_OK
        )


class ChangePasswordView(views.APIView):
    """
    POST /auth/change-password/
    Change password for authenticated user.
    """
    
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary='Change the password',
        description=(
            'Requires the current password. On success the account\'s auth token '
            'is **revoked** - including the one used to make this call - so the '
            'client must log in again with the new password.'
        ),
        tags=['auth'],
        request=ChangePasswordSerializer,
        responses={
            200: DetailResponseSerializer,
            400: OpenApiResponse(
                description=(
                    '`Current password is incorrect`, `New passwords do not match`, '
                    'or a password-policy message on `new_password`.'
                ),
            ),
            401: OpenApiResponse(description='Missing or revoked token.'),
        },
    )
    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data, context={'request': request},
        )
        if serializer.is_valid():
            success, error = AuthService.change_password(
                user=request.user,
                old_password=serializer.validated_data['old_password'],
                new_password=serializer.validated_data['new_password']
            )
            
            if success:
                return Response(
                    {'detail': 'Password changed successfully'},
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {'detail': error},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetTokenView(views.APIView):
    """
    GET /auth/get-token/
    Get auth token for an already authenticated user (for testing).
    Can also use for token refresh.
    """
    
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary='Get the current token',
        description=(
            'Returns the caller\'s existing token, creating one if the row is '
            'missing. Requires authentication, so it is a convenience for '
            'testing rather than a way to obtain a first token - use `login/` '
            'for that.'
        ),
        tags=['auth'],
        responses={
            200: AuthResponseSerializer,
            401: OpenApiResponse(description='Missing or revoked token.'),
        },
    )
    def get(self, request):
        token, _ = Token.objects.get_or_create(user=request.user)
        return Response({
            'token': token.key,
            'user': UserSerializer(request.user).data,
        })