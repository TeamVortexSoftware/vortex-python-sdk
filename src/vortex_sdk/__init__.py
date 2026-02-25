"""
Vortex Python SDK

A Python SDK for Vortex invitation management and JWT generation.
"""

from .types import (
    AcceptInvitationRequest,
    AcceptInvitationsRequest,
    ApiRequestBody,
    ApiResponse,
    ApiResponseJson,
    AuthenticatedUser,
    AutojoinDomain,
    AutojoinDomainsResponse,
    ConfigureAutojoinRequest,
    CreateInvitationRequest,
    GroupInput,
    IdentifierInput,
    Invitation,
    InvitationAcceptance,
    InvitationGroup,
    InvitationResult,
    InvitationTarget,
    JwtPayload,
    SyncInternalInvitationRequest,
    SyncInternalInvitationResponse,
    VortexApiError,
)
from .vortex import Vortex
from .webhook_types import (
    AnalyticsEventType,
    VortexAnalyticsEvent,
    VortexEvent,
    VortexWebhookEvent,
    WebhookEventType,
    is_analytics_event,
    is_webhook_event,
)
from .webhooks import VortexWebhookSignatureError, VortexWebhooks

__version__ = "0.10.0"
__author__ = "TeamVortexSoftware"
__email__ = "support@vortexsoftware.com"

__all__ = [
    "Vortex",
    "AuthenticatedUser",
    "JwtPayload",
    "IdentifierInput",
    "GroupInput",
    "InvitationTarget",
    "InvitationGroup",
    "InvitationAcceptance",
    "InvitationResult",
    "Invitation",  # Alias for InvitationResult
    "CreateInvitationRequest",
    "AcceptInvitationRequest",
    "AcceptInvitationsRequest",  # Alias for AcceptInvitationRequest
    "AutojoinDomain",
    "AutojoinDomainsResponse",
    "ConfigureAutojoinRequest",
    "SyncInternalInvitationRequest",
    "SyncInternalInvitationResponse",
    "ApiResponse",
    "ApiResponseJson",
    "ApiRequestBody",
    "VortexApiError",
    "VortexWebhooks",
    "VortexWebhookSignatureError",
    "VortexWebhookEvent",
    "VortexAnalyticsEvent",
    "VortexEvent",
    "WebhookEventType",
    "AnalyticsEventType",
    "is_webhook_event",
    "is_analytics_event",
]
