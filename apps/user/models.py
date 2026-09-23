from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.

class User(AbstractUser):
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)
    gender = models.CharField(max_length=10, choices=[('male', 'Male'), ('female', 'Female')], null=True, blank=True)

    is_email_verified = models.BooleanField(default=False)
    language = models.CharField(
        max_length=10, 
        default='en',
        choices=[('en', 'English'), ('yo', 'Yoruba'), ('ig', 'Igbo')]
    )
    timezone = models.CharField(max_length=50, default='Africa/Lagos')
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email
    
    def get_full_name(self):
        """Return user's full name."""
        full_name = f'{self.first_name} {self.last_name}'
        return full_name.strip() or self.username