from rest_framework import status
from rest_framework.exceptions import APIException


class EmailDeliveryError(APIException):
    """Raised when an email could not be handed to the mail server.

    Raised from inside a transaction.atomic() block so the writes that the email
    was supposed to accompany are rolled back before DRF renders the response.
    """

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = (
        "We couldn't send the email right now, so nothing was saved. "
        "Please try again in a moment."
    )
    default_code = 'email_delivery_failed'
