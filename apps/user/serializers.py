from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    """Serialize user data."""
    
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'username', 'first_name', 'last_name',
            'full_name', 'phone_number', 'is_email_verified', 'language',
            'timezone', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'is_email_verified', 'created_at', 'updated_at']
    
    # The annotation is what lets the OpenAPI schema type this field; without
    # it a SerializerMethodField comes out as an untyped `any`.
    @extend_schema_field(serializers.CharField())
    def get_full_name(self, obj):
        return obj.get_full_name()