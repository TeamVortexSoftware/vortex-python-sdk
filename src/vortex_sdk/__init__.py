"""
Vortex Python SDK

A Python SDK for Vortex invitation management and JWT generation.
"""

from .vortex import Vortex
from .types import (
    AuthenticatedUser,
    JwtPayload,
    InvitationTarget,
    Invitation,
    CreateInvitationRequest,
    AcceptInvitationsRequest,
    ApiResponse,
    VortexApiError
)

__version__ = "0.0.1"
__author__ = "TeamVortexSoftware"
__email__ = "support@vortexsoftware.com"

__all__ = [
    "Vortex",
    "AuthenticatedUser",
    "JwtPayload",
    "InvitationTarget",
    "Invitation",
    "CreateInvitationRequest",
    "AcceptInvitationsRequest",
    "ApiResponse",
    "VortexApiError",
]