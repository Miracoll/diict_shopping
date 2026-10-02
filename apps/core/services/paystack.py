import hashlib
import hmac
import logging
from decimal import Decimal

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = 15


class PaystackError(Exception):
    """Paystack couldn't be reached, rejected the request, or isn't configured."""


class PaystackService:

    @staticmethod
    def _secret_key():
        key = settings.PAYSTACK_SECRET_KEY
        if not key:
            raise PaystackError('Paystack is not configured')
        return key

    @staticmethod
    def _request(method, path, **kwargs):
        """Call the Paystack API and return the `data` part of its response.

        Paystack wraps every response as {"status": bool, "message": str,
        "data": ...}; a transport failure, a non-2xx status and `status: false`
        all come out of here as PaystackError.
        """
        url = f"{settings.PAYSTACK_BASE_URL.rstrip('/')}{path}"
        headers = {
            'Authorization': f'Bearer {PaystackService._secret_key()}',
            'Content-Type': 'application/json',
        }
        try:
            response = requests.request(
                method, url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS, **kwargs
            )
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            logger.exception('Paystack %s %s failed', method, path)
            raise PaystackError('Could not reach Paystack') from exc

        if not response.ok or not body.get('status'):
            message = body.get('message') or 'Paystack request failed'
            logger.error(
                'Paystack %s %s returned %s: %s', method, path, response.status_code, message
            )
            raise PaystackError(message)

        return body.get('data') or {}

    @staticmethod
    def to_kobo(amount):
        """Naira (Decimal or str) to the integer kobo Paystack works in."""
        return int(Decimal(str(amount)) * 100)

    @staticmethod
    def initialize_transaction(email, amount, reference, callback_url=None, metadata=None):
        """Start a checkout. Returns authorization_url, access_code and reference."""
        payload = {
            'email': email,
            'amount': PaystackService.to_kobo(amount),
            'reference': reference,
            'currency': 'NGN',
        }
        if callback_url:
            payload['callback_url'] = callback_url
        if metadata:
            payload['metadata'] = metadata
        return PaystackService._request('POST', '/transaction/initialize', json=payload)

    @staticmethod
    def verify_transaction(reference):
        """Fetch a transaction's current state from Paystack."""
        return PaystackService._request('GET', f'/transaction/verify/{reference}')

    @staticmethod
    def is_valid_signature(raw_body, signature):
        """Check a webhook's x-paystack-signature: HMAC-SHA512 of the raw body."""
        if not signature or not settings.PAYSTACK_SECRET_KEY:
            return False
        expected = hmac.new(
            settings.PAYSTACK_SECRET_KEY.encode(), raw_body, hashlib.sha512
        ).hexdigest()
        return hmac.compare_digest(expected, signature)
