"""Tests for Vortex webhook signature verification and event construction."""

import hashlib
import hmac
import json

import pytest

from vortex_sdk import (
    VortexAnalyticsEvent,
    VortexWebhookEvent,
    VortexWebhookSignatureError,
    VortexWebhooks,
    is_analytics_event,
    is_webhook_event,
)


SECRET = "whsec_test_secret_123"

WEBHOOK_EVENT_PAYLOAD = json.dumps(
    {
        "id": "evt_123",
        "type": "invitation.accepted",
        "timestamp": "2025-01-15T12:00:00.000Z",
        "accountId": "acc_123",
        "environmentId": "env_456",
        "sourceTable": "invitations",
        "operation": "update",
        "data": {"invitationId": "inv_789", "targetEmail": "user@example.com"},
    }
)

ANALYTICS_EVENT_PAYLOAD = json.dumps(
    {
        "id": "evt_456",
        "name": "widget_loaded",
        "accountId": "acc_123",
        "organizationId": "org_123",
        "projectId": "proj_123",
        "environmentId": "env_456",
        "deploymentId": None,
        "widgetConfigurationId": "wc_123",
        "foreignUserId": "user_123",
        "sessionId": "sess_123",
        "payload": {"page": "/dashboard"},
        "platform": "web",
        "segmentation": None,
        "timestamp": "2025-01-15T12:00:00.000Z",
    }
)


def _sign(payload: str, secret: str = SECRET) -> str:
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


class TestVortexWebhooks:
    def test_constructor_requires_secret(self) -> None:
        with pytest.raises(ValueError, match="requires a secret"):
            VortexWebhooks(secret="")

    def test_verify_signature_valid(self) -> None:
        wh = VortexWebhooks(secret=SECRET)
        sig = _sign(WEBHOOK_EVENT_PAYLOAD)
        assert wh.verify_signature(WEBHOOK_EVENT_PAYLOAD, sig) is True

    def test_verify_signature_invalid(self) -> None:
        wh = VortexWebhooks(secret=SECRET)
        assert wh.verify_signature(WEBHOOK_EVENT_PAYLOAD, "bad_signature") is False

    def test_verify_signature_empty(self) -> None:
        wh = VortexWebhooks(secret=SECRET)
        assert wh.verify_signature(WEBHOOK_EVENT_PAYLOAD, "") is False

    def test_verify_signature_wrong_secret(self) -> None:
        wh = VortexWebhooks(secret=SECRET)
        sig = _sign(WEBHOOK_EVENT_PAYLOAD, "wrong_secret")
        assert wh.verify_signature(WEBHOOK_EVENT_PAYLOAD, sig) is False

    def test_verify_signature_bytes_payload(self) -> None:
        wh = VortexWebhooks(secret=SECRET)
        sig = _sign(WEBHOOK_EVENT_PAYLOAD)
        assert wh.verify_signature(WEBHOOK_EVENT_PAYLOAD.encode("utf-8"), sig) is True

    def test_construct_webhook_event(self) -> None:
        wh = VortexWebhooks(secret=SECRET)
        sig = _sign(WEBHOOK_EVENT_PAYLOAD)
        event = wh.construct_event(WEBHOOK_EVENT_PAYLOAD, sig)
        assert isinstance(event, VortexWebhookEvent)
        assert event.id == "evt_123"
        assert event.type == "invitation.accepted"
        assert event.account_id == "acc_123"
        assert event.data["targetEmail"] == "user@example.com"

    def test_construct_analytics_event(self) -> None:
        wh = VortexWebhooks(secret=SECRET)
        sig = _sign(ANALYTICS_EVENT_PAYLOAD)
        event = wh.construct_event(ANALYTICS_EVENT_PAYLOAD, sig)
        assert isinstance(event, VortexAnalyticsEvent)
        assert event.id == "evt_456"
        assert event.name == "widget_loaded"
        assert event.account_id == "acc_123"

    def test_construct_event_bad_signature(self) -> None:
        wh = VortexWebhooks(secret=SECRET)
        with pytest.raises(VortexWebhookSignatureError):
            wh.construct_event(WEBHOOK_EVENT_PAYLOAD, "bad_sig")


class TestTypeGuards:
    def test_is_webhook_event(self) -> None:
        assert is_webhook_event({"type": "invitation.accepted", "id": "1"}) is True
        assert is_webhook_event({"name": "widget_loaded", "id": "1"}) is False

    def test_is_analytics_event(self) -> None:
        assert is_analytics_event({"name": "widget_loaded", "id": "1"}) is True
        assert is_analytics_event({"type": "invitation.accepted", "id": "1"}) is False
