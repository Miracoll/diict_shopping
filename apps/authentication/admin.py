from django.contrib import admin
from django.utils.html import format_html
from .models import EmailVerificationToken, PasswordResetToken, LoginAttempt

@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    """Admin for email verification tokens."""
    
    list_display = (
        'user_email', 'token', 'is_used', 'is_expired', 'created_at'
    )
    list_filter = ('is_used', 'expires_at', 'created_at')
    search_fields = ('user__email', 'token', 'token_uuid')
    readonly_fields = ('token', 'token_uuid', 'created_at', 'updated_at')
    date_hierarchy = 'created_at'
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def is_expired(self, obj):
        if not obj.is_valid():
            return format_html(
                '<span style="color: red;">✗ Expired</span>'
            )
        return format_html(
            '<span style="color: green;">✓ Valid</span>'
        )
    is_expired.short_description = 'Status'


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    """Admin for password reset tokens."""
    
    list_display = (
        'user_email', 'token', 'is_used', 'is_expired', 'created_at'
    )
    list_filter = ('is_used', 'expires_at', 'created_at')
    search_fields = ('user__email', 'token', 'token_uuid')
    readonly_fields = ('token', 'token_uuid', 'created_at')
    date_hierarchy = 'created_at'
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User Email'
    
    def is_expired(self, obj):
        if not obj.is_valid():
            return format_html(
                '<span style="color: red;">✗ Expired</span>'
            )
        return format_html(
            '<span style="color: green;">✓ Valid</span>'
        )
    is_expired.short_description = 'Status'


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """Admin for login attempts tracking."""
    
    list_display = ('email', 'ip_address', 'status', 'created_at')
    list_filter = ('success', 'created_at')
    search_fields = ('email', 'ip_address')
    readonly_fields = ('created_at', 'email', 'ip_address', 'success', 'error_message')
    date_hierarchy = 'created_at'
    
    def status(self, obj):
        if obj.success:
            return format_html(
                '<span style="color: green;">✓ Success</span>'
            )
        return format_html(
            '<span style="color: red;">✗ Failed</span>'
        )
    status.short_description = 'Status'
    
    def has_add_permission(self, request):
        """Disable manual creation of login attempts."""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Allow deletion for auditing."""
        return request.user.is_superuser