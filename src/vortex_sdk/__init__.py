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
    VortexApiError,
)
from .vortex import Vortex

__version__ = "0.7.0"
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
    "ApiResponse",
    "ApiResponseJson",
    "ApiRequestBody",
    "VortexApiError",
]
