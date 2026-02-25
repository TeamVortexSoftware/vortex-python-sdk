"""
Vortex Webhook Types

Type definitions for webhook event handling.
These mirror the server-side types but are kept independent
so the SDK has no internal dependencies.

@see DEV-1769
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


# ─── Webhook Event Type Constants ──────────────────────────────────────


class WebhookEventType(str, Enum):
    """Webhook event types for Vortex state changes."""

    # Invitation Lifecycle
    INVITATION_CREATED = "invitation.created"
    INVITATION_ACCEPTED = "invitation.accepted"
    INVITATION_DEACTIVATED = "invitation.deactivated"
    INVITATION_EMAIL_DELIVERED = "invitation.email.delivered"
    INVITATION_EMAIL_BOUNCED = "invitation.email.bounced"
    INVITATION_EMAIL_OPENED = "invitation.email.opened"
    INVITATION_LINK_CLICKED = "invitation.link.clicked"
    INVITATION_REMINDER_SENT = "invitation.reminder.sent"

    # Deployment Lifecycle
    DEPLOYMENT_CREATED = "deployment.created"
    DEPLOYMENT_DEACTIVATED = "deployment.deactivated"

    # A/B Testing
    ABTEST_STARTED = "abtest.started"
    ABTEST_WINNER_DECLARED = "abtest.winner_declared"

    # Member/Group
    MEMBER_CREATED = "member.created"
    GROUP_MEMBER_ADDED = "group.member.added"

    # Email
    EMAIL_COMPLAINED = "email.complained"


class AnalyticsEventType(str, Enum):
    """Analytics event types for behavioral telemetry."""

    WIDGET_LOADED = "widget_loaded"
    INVITATION_SENT = "invitation_sent"
    INVITATION_CLICKED = "invitation_clicked"
    INVITATION_ACCEPTED = "invitation_accepted"
    SHARE_TRIGGERED = "share_triggered"


# ─── Webhook Event Payload ─────────────────────────────────────────────


class VortexWebhookEvent(BaseModel):
    """A Vortex webhook event representing a server-side state change."""

    id: str
    type: str
    timestamp: str
    account_id: str = Field(alias="accountId")
    environment_id: Optional[str] = Field(None, alias="environmentId")
    source_table: str = Field(alias="sourceTable")
    operation: str  # "insert" | "update" | "delete"
    data: Dict[str, Any]

    class Config:
        populate_by_name = True


# ─── Analytics Event Payload ───────────────────────────────────────────


class VortexAnalyticsEvent(BaseModel):
    """An analytics event representing client-side behavioral telemetry."""

    id: str
    name: str
    account_id: str = Field(alias="accountId")
    organization_id: str = Field(alias="organizationId")
    project_id: str = Field(alias="projectId")
    environment_id: str = Field(alias="environmentId")
    deployment_id: Optional[str] = Field(None, alias="deploymentId")
    widget_configuration_id: Optional[str] = Field(
        None, alias="widgetConfigurationId"
    )
    foreign_user_id: Optional[str] = Field(None, alias="foreignUserId")
    session_id: Optional[str] = Field(None, alias="sessionId")
    payload: Optional[Dict[str, Any]] = None
    platform: Optional[str] = None
    segmentation: Optional[str] = None
    timestamp: str

    class Config:
        populate_by_name = True


# ─── Union & Discriminator ─────────────────────────────────────────────

VortexEvent = Union[VortexWebhookEvent, VortexAnalyticsEvent]


def is_webhook_event(event: Dict[str, Any]) -> bool:
    """Returns True if the event dict is a webhook event (has 'type', no 'name')."""
    return "type" in event and "name" not in event


def is_analytics_event(event: Dict[str, Any]) -> bool:
    """Returns True if the event dict is an analytics event (has 'name')."""
    return "name" in event
