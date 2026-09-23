from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token

User = get_user_model()


@receiver(post_save, sender=User)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)


@receiver(post_save, sender=User)
def create_email_verification_token(sender, instance=None, created=False, **kwargs):
    """Every new user gets a pending verification code. The email itself is
    sent by AuthService.create_user / the resend endpoint, not from here."""
    if created:
        from .services import AuthService
        AuthService.create_email_verification_token(instance)
