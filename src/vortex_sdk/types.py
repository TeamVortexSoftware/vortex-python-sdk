from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field


class IdentifierInput(BaseModel):
    """Identifier structure for JWT generation"""

    type: Literal["email", "sms"]
    value: str


class GroupInput(BaseModel):
    """Group structure for JWT generation (input)"""

    type: str
    id: Optional[str] = None  # Legacy field (deprecated, use groupId)
    groupId: Optional[str] = Field(
        None, alias="group_id", serialization_alias="groupId"
    )  # Preferred: Customer's group ID
    name: str

    class Config:
        populate_by_name = True


class InvitationGroup(BaseModel):
    """
    Invitation group from API responses
    This matches the MemberGroups table structure from the API
    """

    id: str  # Vortex internal UUID
    account_id: str = Field(alias="accountId")  # Vortex account ID
    group_id: str = Field(alias="groupId")  # Customer's group ID
    type: str  # Group type (e.g., "workspace", "team")
    name: str  # Group name
    created_at: str = Field(alias="createdAt")  # ISO 8601 timestamp

    class Config:
        # Allow both snake_case (Python) and camelCase (JSON) field names
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "accountId": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                "groupId": "workspace-123",
                "type": "workspace",
                "name": "My Workspace",
                "createdAt": "2025-01-27T12:00:00.000Z",
            }
        }


class AuthenticatedUser(BaseModel):
    user_id: str
    identifiers: List[IdentifierInput]
    groups: Optional[List[GroupInput]] = None
    role: Optional[str] = None


class JwtPayload(BaseModel):
    user_id: str
    identifiers: List[IdentifierInput]
    groups: Optional[List[GroupInput]] = None
    role: Optional[str] = None
    attributes: Optional[Dict[str, Any]] = None


class InvitationTarget(BaseModel):
    type: Literal["email", "sms"]
    value: str


class InvitationAcceptance(BaseModel):
    """Represents an acceptance of an invitation"""

    id: str
    account_id: str = Field(alias="accountId")
    project_id: str = Field(alias="projectId")
    accepted_at: str = Field(alias="acceptedAt")
    target: InvitationTarget

    class Config:
        populate_by_name = True


class InvitationResult(BaseModel):
    """
    Complete invitation result from API responses.
    This is the exact port of the Node.js SDK's InvitationResult type.
    """

    id: str
    account_id: str = Field(alias="accountId")
    click_throughs: int = Field(alias="clickThroughs")
    configuration_attributes: Optional[Dict[str, Any]] = Field(
        None, alias="configurationAttributes"
    )
    attributes: Optional[Dict[str, Any]] = None
    created_at: str = Field(alias="createdAt")
    deactivated: bool
    delivery_count: int = Field(alias="deliveryCount")
    delivery_types: List[Literal["email", "sms", "share"]] = Field(
        alias="deliveryTypes"
    )
    foreign_creator_id: str = Field(alias="foreignCreatorId")
    invitation_type: Literal["single_use", "multi_use"] = Field(alias="invitationType")
    modified_at: Optional[str] = Field(None, alias="modifiedAt")
    status: Literal[
        "queued",
        "sending",
        "delivered",
        "accepted",
        "shared",
        "unfurled",
        "accepted_elsewhere",
    ]
    target: List[InvitationTarget]
    views: int
    widget_configuration_id: str = Field(alias="widgetConfigurationId")
    project_id: str = Field(alias="projectId")
    groups: List[Optional[InvitationGroup]] = Field(default_factory=list)
    accepts: List[InvitationAcceptance] = Field(default_factory=list)

    class Config:
        populate_by_name = True


# Alias for backward compatibility
Invitation = InvitationResult


class CreateInvitationRequest(BaseModel):
    target: InvitationTarget
    group_type: Optional[str] = None
    group_id: Optional[str] = None
    expires_at: Optional[str] = None
    metadata: Optional[Dict[str, Union[str, int, bool]]] = None


class AcceptInvitationRequest(BaseModel):
    """Request to accept one or more invitations"""

    invitation_ids: List[str] = Field(alias="invitationIds")
    target: InvitationTarget

    class Config:
        populate_by_name = True


# Alias for backward compatibility
AcceptInvitationsRequest = AcceptInvitationRequest


class ApiResponse(BaseModel):
    data: Optional[Dict] = None
    error: Optional[str] = None
    status_code: int = 200


class VortexApiError(Exception):
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


# Type aliases to match Node.js SDK
ApiResponseJson = Union[
    InvitationResult, Dict[str, List[InvitationResult]], Dict[str, Any]
]
ApiRequestBody = Union[AcceptInvitationRequest, None]
