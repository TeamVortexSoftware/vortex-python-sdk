"""
Vortex Webhooks

Core webhook verification and parsing for the Vortex Python SDK.

Example::

    from vortex_sdk import VortexWebhooks

    webhooks = VortexWebhooks(secret=os.environ["VORTEX_WEBHOOK_SECRET"])

    # In any HTTP handler:
    event = webhooks.construct_event(raw_body, signature_header)

@see DEV-1769
"""

import hashlib
import hmac
import json
from typing import Any, Dict, Union

from .webhook_types import (
    VortexAnalyticsEvent,
    VortexEvent,
    VortexWebhookEvent,
    is_analytics_event,
    is_webhook_event,
)


class VortexWebhookSignatureError(Exception):
    """Raised when webhook signature verification fails."""

    pass


class VortexWebhooks:
    """
    Core webhook verification and parsing.

    This class is framework-agnostic — use it directly or with
    framework-specific integrations (Flask, Django, FastAPI).

    Args:
        secret: The webhook signing secret from your Vortex dashboard.

    Example::

        from vortex_sdk import VortexWebhooks

        webhooks = VortexWebhooks(secret=os.environ["VORTEX_WEBHOOK_SECRET"])
        event = webhooks.construct_event(request.body, request.headers["X-Vortex-Signature"])
    """

    def __init__(self, secret: str) -> None:
        if not secret:
            raise ValueError("VortexWebhooks requires a secret")
        self._secret = secret

    def verify_signature(self, payload: Union[str, bytes], signature: str) -> bool:
        """
        Verify the HMAC-SHA256 signature of an incoming webhook payload.

        Args:
            payload: The raw request body (str or bytes).
            signature: The value of the ``X-Vortex-Signature`` header.

        Returns:
            ``True`` if the signature is valid.
        """
        if not signature:
            return False

        if isinstance(payload, str):
            payload = payload.encode("utf-8")

        expected = hmac.new(
            self._secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()

        # Timing-safe comparison to prevent timing attacks
        return hmac.compare_digest(signature, expected)

    def construct_event(
        self, payload: Union[str, bytes], signature: str
    ) -> VortexEvent:
        """
        Verify and parse an incoming webhook payload.

        Args:
            payload: The raw request body (str or bytes). Must be the raw body,
                not a parsed dict — signature verification requires the exact
                bytes that were signed.
            signature: The value of the ``X-Vortex-Signature`` header.

        Returns:
            A :class:`VortexWebhookEvent` or :class:`VortexAnalyticsEvent`.

        Raises:
            VortexWebhookSignatureError: If the signature is invalid.
        """
        if not self.verify_signature(payload, signature):
            raise VortexWebhookSignatureError(
                "Webhook signature verification failed. Ensure you are using "
                "the raw request body and the correct signing secret."
            )

        body = payload if isinstance(payload, str) else payload.decode("utf-8")
        parsed: Dict[str, Any] = json.loads(body)

        if is_webhook_event(parsed):
            return VortexWebhookEvent(**parsed)
        elif is_analytics_event(parsed):
            return VortexAnalyticsEvent(**parsed)
        else:
            # Return as webhook event by default
            return VortexWebhookEvent(**parsed)
