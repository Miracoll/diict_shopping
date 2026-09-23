# auth/urls.py
from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    VerifyEmailView,
    ResendVerificationEmailView,
    ForgotPasswordView,
    ResetPasswordView,
    CurrentUserView,
    LogoutView,
    ChangePasswordView,
    GetTokenView,
)

app_name = 'auth'

urlpatterns = [
    # Public endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend-verification'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),

    # Authenticated endpoints
    path('me/', CurrentUserView.as_view(), name='current-user'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('get-token/', GetTokenView.as_view(), name='get-token'),
]