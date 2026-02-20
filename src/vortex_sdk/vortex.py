import base64
import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any, Dict, List, Literal, Optional, Union

import httpx

logger = logging.getLogger(__name__)

from .types import (
    AcceptUser,
    AutojoinDomainsResponse,
    BackendCreateInvitationRequest,
    ConfigureAutojoinRequest,
    CreateInvitationGroup,
    CreateInvitationResponse,
    CreateInvitationTarget,
    Invitation,
    InvitationTarget,
    Inviter,
    SyncInternalInvitationRequest,
    SyncInternalInvitationResponse,
    User,
    VortexApiError,
)


def _get_version() -> str:
    """Lazy import of version to avoid circular import"""
    from . import __version__

    return __version__


class Vortex:
    def __init__(
        self, api_key: str, base_url: str = "https://api.vortexsoftware.com/api/v1"
    ):
        """
        Initialize Vortex client

        Args:
            api_key: Your Vortex API key
            base_url: Base URL for Vortex API (default: https://api.vortexsoftware.com/api/v1)
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient()
        self._sync_client = httpx.Client()

    def generate_jwt(self, user: Union[User, Dict], **extra: Any) -> str:
        """
        Generate a JWT token for a user

        Args:
            user: User object or dict with 'id', 'email', and optional 'name',
                  'avatar_url', 'admin_scopes'
            **extra: Additional properties to include in JWT payload

        Returns:
            JWT token string

        Raises:
            ValueError: If API key format is invalid or required fields are missing

        Example:
            user = {'id': 'user-123', 'email': 'user@example.com', 'admin_scopes': ['autojoin']}
            jwt = vortex.generate_jwt(user=user)

            # With additional properties including name and avatar
            user = {
                'id': 'user-123',
                'email': 'user@example.com',
                'name': 'John Doe',
                'avatar_url': 'https://example.com/avatar.jpg'
            }
            jwt = vortex.generate_jwt(user=user, role='admin', department='Engineering')
        """
        # Convert dict to User if needed
        if isinstance(user, dict):
            user = User(**user)

        # Parse API key (format: VRTX.base64url(uuid).key)
        parts = self.api_key.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid API key format. Expected: VRTX.{encodedId}.{key}")

        prefix, encoded_id, key = parts

        if prefix != "VRTX":
            raise ValueError("Invalid API key prefix. Expected: VRTX")

        # Decode UUID from base64url
        # Add padding if needed
        padding = 4 - len(encoded_id) % 4
        if padding != 4:
            encoded_id_padded = encoded_id + ("=" * padding)
        else:
            encoded_id_padded = encoded_id

        try:
            uuid_bytes = base64.urlsafe_b64decode(encoded_id_padded)
            kid = str(uuid.UUID(bytes=uuid_bytes))
        except Exception as e:
            raise ValueError(f"Invalid UUID in API key: {e}") from e

        # Generate timestamps
        iat = int(time.time())
        expires = iat + 3600

        # Step 1: Derive signing key from API key + UUID
        signing_key = hmac.new(key.encode(), kid.encode(), hashlib.sha256).digest()

        # Step 2: Build header + payload
        header = {
            "iat": iat,
            "alg": "HS256",
            "typ": "JWT",
            "kid": kid,
        }

        # Build JWT payload
        jwt_payload: Dict[str, Any] = {
            "userId": user.id,
            "userEmail": user.email,
            "expires": expires,
        }

        # Add userName if present
        if user.user_name:
            jwt_payload["userName"] = user.user_name

        # Add userAvatarUrl if present
        if user.user_avatar_url:
            jwt_payload["userAvatarUrl"] = user.user_avatar_url

        # Add adminScopes if present
        if user.admin_scopes:
            jwt_payload["adminScopes"] = user.admin_scopes

        # Add allowedEmailDomains if present (for domain-restricted invitations)
        if user.allowed_email_domains:
            jwt_payload["allowedEmailDomains"] = user.allowed_email_domains

        # Add any additional properties from user.model_extra
        if hasattr(user, "model_extra") and user.model_extra:
            jwt_payload.update(user.model_extra)

        # Add any additional properties from **extra
        if extra:
            jwt_payload.update(extra)

        # Step 3: Base64URL encode (without padding)
        header_json = json.dumps(header, separators=(",", ":"))
        payload_json = json.dumps(jwt_payload, separators=(",", ":"))

        header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip("=")
        payload_b64 = (
            base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
        )

        # Step 4: Sign
        to_sign = f"{header_b64}.{payload_b64}"
        signature = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).digest()

        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

        return f"{to_sign}.{signature_b64}"

    async def _vortex_api_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Dict:
        """
        Make an API request to Vortex

        Args:
            method: HTTP method (GET, POST, DELETE, etc.)
            endpoint: API endpoint path
            data: Request body data
            params: Query parameters

        Returns:
            API response data

        Raises:
            VortexApiError: If the API request fails
        """
        url = f"{self.base_url}{endpoint}"
        headers = {
            "x-api-key": f"{self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"vortex-python-sdk/{_get_version()}",
            "x-vortex-sdk-name": "vortex-python-sdk",
            "x-vortex-sdk-version": _get_version(),
        }

        try:
            response = await self._client.request(
                method=method, url=url, json=data, params=params, headers=headers
            )

            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_message = error_data.get(
                        "error",
                        f"API request failed with status {response.status_code}",
                    )
                except Exception:
                    error_message = (
                        f"API request failed with status {response.status_code}"
                    )

                raise VortexApiError(error_message, response.status_code)

            # Handle empty responses (e.g., DELETE requests may return 204 or empty 200)
            if response.status_code == 204 or not response.content:
                return {}  # type: ignore[return-value]

            return response.json()  # type: ignore[no-any-return]

        except httpx.RequestError as e:
            raise VortexApiError(f"Request failed: {str(e)}") from e

    def _vortex_api_request_sync(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Dict:
        """
        Make a synchronous API request to Vortex

        Args:
            method: HTTP method (GET, POST, DELETE, etc.)
            endpoint: API endpoint path
            data: Request body data
            params: Query parameters

        Returns:
            API response data

        Raises:
            VortexApiError: If the API request fails
        """
        url = f"{self.base_url}{endpoint}"
        headers = {
            "x-api-key": f"{self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"vortex-python-sdk/{_get_version()}",
            "x-vortex-sdk-name": "vortex-python-sdk",
            "x-vortex-sdk-version": _get_version(),
        }

        try:
            response = self._sync_client.request(
                method=method, url=url, json=data, params=params, headers=headers
            )

            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_message = error_data.get(
                        "error",
                        f"API request failed with status {response.status_code}",
                    )
                except Exception:
                    error_message = (
                        f"API request failed with status {response.status_code}"
                    )

                raise VortexApiError(error_message, response.status_code)

            # Handle empty responses (e.g., DELETE requests may return 204 or empty 200)
            if response.status_code == 204 or not response.content:
                return {}  # type: ignore[return-value]

            return response.json()  # type: ignore[no-any-return]

        except httpx.RequestError as e:
            raise VortexApiError(f"Request failed: {str(e)}") from e

    async def get_invitations_by_target(
        self,
        target_type: Literal["email", "username", "phoneNumber"],
        target_value: str,
    ) -> List[Invitation]:
        """
        Get invitations for a specific target

        Args:
            target_type: Type of target (email, username, or phoneNumber)
            target_value: Target value

        Returns:
            List of invitations
        """
        params = {"targetType": target_type, "targetValue": target_value}

        response = await self._vortex_api_request(
            "GET", "/invitations", params=params
        )
        return [Invitation(**inv) for inv in response.get("invitations", [])]

    def get_invitations_by_target_sync(
        self,
        target_type: Literal["email", "username", "phoneNumber"],
        target_value: str,
    ) -> List[Invitation]:
        """
        Get invitations for a specific target (synchronous)

        Args:
            target_type: Type of target (email, username, or phoneNumber)
            target_value: Target value

        Returns:
            List of invitations
        """
        params = {"targetType": target_type, "targetValue": target_value}

        response = self._vortex_api_request_sync(
            "GET", "/invitations", params=params
        )
        return [Invitation(**inv) for inv in response.get("invitations", [])]

    async def get_invitation(self, invitation_id: str) -> Invitation:
        """
        Get a specific invitation by ID

        Args:
            invitation_id: Invitation ID

        Returns:
            Invitation object
        """
        response = await self._vortex_api_request(
            "GET", f"/invitations/{invitation_id}"
        )
        return Invitation(**response)

    def get_invitation_sync(self, invitation_id: str) -> Invitation:
        """
        Get a specific invitation by ID (synchronous)

        Args:
            invitation_id: Invitation ID

        Returns:
            Invitation object
        """
        response = self._vortex_api_request_sync("GET", f"/invitations/{invitation_id}")
        return Invitation(**response)

    async def accept_invitations(
        self,
        invitation_ids: List[str],
        user_or_target: Union[AcceptUser, InvitationTarget, Dict[str, Any], List[Union[InvitationTarget, Dict[str, str]]]],
    ) -> Dict:
        """
        Accept multiple invitations using the new User format (preferred)

        Args:
            invitation_ids: List of invitation IDs to accept
            user_or_target: User object with email/phone/name (preferred) OR legacy target format (deprecated)

        Returns:
            API response

        Example (new format):
            user = AcceptUser(email="user@example.com", name="John Doe")
            result = await client.accept_invitations(["inv-123"], user)

        Example (legacy format - deprecated):
            target = InvitationTarget(type="email", value="user@example.com")
            result = await client.accept_invitations(["inv-123"], target)
        """
        # Check if it's a list of targets (legacy format with multiple targets)
        if isinstance(user_or_target, list):
            logger.warning(
                "[Vortex SDK] DEPRECATED: Passing a list of targets is deprecated. "
                "Use the AcceptUser format and call once per user instead."
            )
            if not user_or_target:
                raise ValueError("No targets provided")

            last_result = None
            last_exception = None

            for target in user_or_target:
                try:
                    last_result = await self.accept_invitations(invitation_ids, target)
                except Exception as e:
                    last_exception = e

            if last_exception:
                raise last_exception

            return last_result or {}

        # Check if it's a legacy InvitationTarget
        is_legacy_target = isinstance(user_or_target, InvitationTarget) or (
            isinstance(user_or_target, dict)
            and "type" in user_or_target
            and "value" in user_or_target
        )

        if is_legacy_target:
            logger.warning(
                "[Vortex SDK] DEPRECATED: Passing an InvitationTarget is deprecated. "
                "Use the AcceptUser format instead: AcceptUser(email='user@example.com')"
            )

            # Convert target to User format
            if isinstance(user_or_target, InvitationTarget):
                target_type = user_or_target.type
                target_value = user_or_target.value
            else:
                target_type = user_or_target["type"]
                target_value = user_or_target["value"]

            user = AcceptUser()
            if target_type == "email":
                user.email = target_value
            elif target_type in ("phone", "phoneNumber"):
                user.phone = target_value
            else:
                # For other types, try to use as email
                user.email = target_value

            # Recursively call with User format
            return await self.accept_invitations(invitation_ids, user)

        # New User format
        if isinstance(user_or_target, dict):
            user = AcceptUser(**user_or_target)
        else:
            user = user_or_target

        # Validate that either email or phone is provided
        if not user.email and not user.phone:
            raise ValueError("User must have either email or phone")

        data = {"invitationIds": invitation_ids, "user": user.model_dump(exclude_none=True)}

        return await self._vortex_api_request("POST", "/invitations/accept", data=data)

    async def accept_invitation(
        self,
        invitation_id: str,
        user: Union[AcceptUser, Dict[str, Any]],
    ) -> Dict:
        """
        Accept a single invitation (recommended method)

        This is the recommended method for accepting invitations.

        Args:
            invitation_id: Single invitation ID to accept
            user: User object with email/phone/name

        Returns:
            API response

        Example:
            user = AcceptUser(email="user@example.com", name="John Doe")
            result = await client.accept_invitation("inv-123", user)

            # Or with a dict:
            result = await client.accept_invitation("inv-123", {"email": "user@example.com"})
        """
        return await self.accept_invitations([invitation_id], user)

    def accept_invitation_sync(
        self,
        invitation_id: str,
        user: Union[AcceptUser, Dict[str, Any]],
    ) -> Dict:
        """
        Accept a single invitation (synchronous, recommended method)

        This is the recommended method for accepting invitations.

        Args:
            invitation_id: Single invitation ID to accept
            user: User object with email/phone/name

        Returns:
            API response

        Example:
            user = AcceptUser(email="user@example.com", name="John Doe")
            result = client.accept_invitation_sync("inv-123", user)

            # Or with a dict:
            result = client.accept_invitation_sync("inv-123", {"email": "user@example.com"})
        """
        return self.accept_invitations_sync([invitation_id], user)

    def accept_invitations_sync(
        self,
        invitation_ids: List[str],
        user_or_target: Union[AcceptUser, InvitationTarget, Dict[str, Any], List[Union[InvitationTarget, Dict[str, str]]]],
    ) -> Dict:
        """
        Accept multiple invitations using the new User format (synchronous version)

        Args:
            invitation_ids: List of invitation IDs to accept
            user_or_target: User object with email/phone/name (preferred) OR legacy target format (deprecated)

        Returns:
            API response

        Example (new format):
            user = AcceptUser(email="user@example.com", name="John Doe")
            result = client.accept_invitations_sync(["inv-123"], user)

        Example (legacy format - deprecated):
            target = InvitationTarget(type="email", value="user@example.com")
            result = client.accept_invitations_sync(["inv-123"], target)
        """
        # Check if it's a list of targets (legacy format with multiple targets)
        if isinstance(user_or_target, list):
            logger.warning(
                "[Vortex SDK] DEPRECATED: Passing a list of targets is deprecated. "
                "Use the AcceptUser format and call once per user instead."
            )
            if not user_or_target:
                raise ValueError("No targets provided")

            last_result = None
            last_exception = None

            for target in user_or_target:
                try:
                    last_result = self.accept_invitations_sync(invitation_ids, target)
                except Exception as e:
                    last_exception = e

            if last_exception:
                raise last_exception

            return last_result or {}

        # Check if it's a legacy InvitationTarget
        is_legacy_target = isinstance(user_or_target, InvitationTarget) or (
            isinstance(user_or_target, dict)
            and "type" in user_or_target
            and "value" in user_or_target
        )

        if is_legacy_target:
            logger.warning(
                "[Vortex SDK] DEPRECATED: Passing an InvitationTarget is deprecated. "
                "Use the AcceptUser format instead: AcceptUser(email='user@example.com')"
            )

            # Convert target to User format
            if isinstance(user_or_target, InvitationTarget):
                target_type = user_or_target.type
                target_value = user_or_target.value
            else:
                target_type = user_or_target["type"]
                target_value = user_or_target["value"]

            user = AcceptUser()
            if target_type == "email":
                user.email = target_value
            elif target_type in ("phone", "phoneNumber"):
                user.phone = target_value
            else:
                # For other types, try to use as email
                user.email = target_value

            # Recursively call with User format
            return self.accept_invitations_sync(invitation_ids, user)

        # New User format
        if isinstance(user_or_target, dict):
            user = AcceptUser(**user_or_target)
        else:
            user = user_or_target

        # Validate that either email or phone is provided
        if not user.email and not user.phone:
            raise ValueError("User must have either email or phone")

        data = {"invitationIds": invitation_ids, "user": user.model_dump(exclude_none=True)}

        return self._vortex_api_request_sync("POST", "/invitations/accept", data=data)

    async def revoke_invitation(self, invitation_id: str) -> Dict:
        """
        Revoke an invitation

        Args:
            invitation_id: Invitation ID to revoke

        Returns:
            API response
        """
        return await self._vortex_api_request("DELETE", f"/invitations/{invitation_id}")

    def revoke_invitation_sync(self, invitation_id: str) -> Dict:
        """
        Revoke an invitation (synchronous)

        Args:
            invitation_id: Invitation ID to revoke

        Returns:
            API response
        """
        return self._vortex_api_request_sync("DELETE", f"/invitations/{invitation_id}")

    async def get_invitations_by_group(
        self, group_type: str, group_id: str
    ) -> List[Invitation]:
        """
        Get invitations for a specific group

        Args:
            group_type: Type of group
            group_id: Group ID

        Returns:
            List of invitations
        """
        response = await self._vortex_api_request(
            "GET", f"/invitations/by-group/{group_type}/{group_id}"
        )
        return [Invitation(**inv) for inv in response.get("invitations", [])]

    def get_invitations_by_group_sync(
        self, group_type: str, group_id: str
    ) -> List[Invitation]:
        """
        Get invitations for a specific group (synchronous)

        Args:
            group_type: Type of group
            group_id: Group ID

        Returns:
            List of invitations
        """
        response = self._vortex_api_request_sync(
            "GET", f"/invitations/by-group/{group_type}/{group_id}"
        )
        return [Invitation(**inv) for inv in response.get("invitations", [])]

    async def delete_invitations_by_group(self, group_type: str, group_id: str) -> Dict:
        """
        Delete all invitations for a specific group

        Args:
            group_type: Type of group
            group_id: Group ID

        Returns:
            API response
        """
        return await self._vortex_api_request(
            "DELETE", f"/invitations/by-group/{group_type}/{group_id}"
        )

    def delete_invitations_by_group_sync(self, group_type: str, group_id: str) -> Dict:
        """
        Delete all invitations for a specific group (synchronous)

        Args:
            group_type: Type of group
            group_id: Group ID

        Returns:
            API response
        """
        return self._vortex_api_request_sync(
            "DELETE", f"/invitations/by-group/{group_type}/{group_id}"
        )

    async def reinvite(self, invitation_id: str) -> Invitation:
        """
        Reinvite for a specific invitation

        Args:
            invitation_id: Invitation ID to reinvite

        Returns:
            Updated invitation object
        """
        response = await self._vortex_api_request(
            "POST", f"/invitations/{invitation_id}/reinvite"
        )
        return Invitation(**response)

    def reinvite_sync(self, invitation_id: str) -> Invitation:
        """
        Reinvite for a specific invitation (synchronous)

        Args:
            invitation_id: Invitation ID to reinvite

        Returns:
            Updated invitation object
        """
        response = self._vortex_api_request_sync(
            "POST", f"/invitations/{invitation_id}/reinvite"
        )
        return Invitation(**response)

    async def create_invitation(
        self,
        widget_configuration_id: str,
        target: Union[CreateInvitationTarget, Dict[str, str]],
        inviter: Union[Inviter, Dict[str, str]],
        groups: Optional[List[Union[CreateInvitationGroup, Dict[str, str]]]] = None,
        source: Optional[str] = None,
        template_variables: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CreateInvitationResponse:
        """
        Create an invitation from your backend.

        This method allows you to create invitations programmatically using your API key,
        without requiring a user JWT token. Useful for server-side invitation creation,
        such as "People You May Know" flows or admin-initiated invitations.

        Args:
            widget_configuration_id: The widget configuration ID to use
            target: The target of the invitation (who is being invited)
                   - type: 'email', 'phone', or 'internal'
                   - value: Email address, phone number, or internal user ID
            inviter: Information about the user creating the invitation
                    - user_id: Your internal user ID for the inviter (required)
                    - user_email: Optional email of the inviter
                    - name: Optional display name of the inviter
            groups: Optional groups/scopes to associate with the invitation
            source: Optional source for analytics (defaults to 'api')
            template_variables: Optional template variables for email customization
            metadata: Optional metadata passed through to webhooks

        Returns:
            CreateInvitationResponse with id, short_link, status, and created_at

        Example:
            # Create an email invitation
            result = await vortex.create_invitation(
                widget_configuration_id="widget-config-123",
                target={"type": "email", "value": "invitee@example.com"},
                inviter={"user_id": "user-456", "user_email": "inviter@example.com"},
                groups=[{"type": "team", "group_id": "team-789", "name": "Engineering"}],
            )

            # Create an internal invitation (PYMK flow - no email sent)
            result = await vortex.create_invitation(
                widget_configuration_id="widget-config-123",
                target={"type": "internal", "value": "internal-user-abc"},
                inviter={"user_id": "user-456"},
                source="pymk",
            )
        """
        # Convert dicts to models if needed
        if isinstance(target, dict):
            target = CreateInvitationTarget(**target)
        if isinstance(inviter, dict):
            inviter = Inviter(**inviter)
        if groups:
            groups = [
                CreateInvitationGroup(**g) if isinstance(g, dict) else g
                for g in groups
            ]

        request = BackendCreateInvitationRequest(
            widget_configuration_id=widget_configuration_id,
            target=target,
            inviter=inviter,
            groups=groups,
            source=source,
            template_variables=template_variables,
            metadata=metadata,
        )

        # Use by_alias=True to get camelCase keys for the API
        response = await self._vortex_api_request(
            "POST", "/invitations", data=request.model_dump(by_alias=True, exclude_none=True)
        )
        return CreateInvitationResponse(**response)

    def create_invitation_sync(
        self,
        widget_configuration_id: str,
        target: Union[CreateInvitationTarget, Dict[str, str]],
        inviter: Union[Inviter, Dict[str, str]],
        groups: Optional[List[Union[CreateInvitationGroup, Dict[str, str]]]] = None,
        source: Optional[str] = None,
        template_variables: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CreateInvitationResponse:
        """
        Create an invitation from your backend (synchronous version).

        See create_invitation() for full documentation.

        Example:
            result = vortex.create_invitation_sync(
                widget_configuration_id="widget-config-123",
                target={"type": "email", "value": "invitee@example.com"},
                inviter={"user_id": "user-456"},
            )
        """
        # Convert dicts to models if needed
        if isinstance(target, dict):
            target = CreateInvitationTarget(**target)
        if isinstance(inviter, dict):
            inviter = Inviter(**inviter)
        if groups:
            groups = [
                CreateInvitationGroup(**g) if isinstance(g, dict) else g
                for g in groups
            ]

        request = BackendCreateInvitationRequest(
            widget_configuration_id=widget_configuration_id,
            target=target,
            inviter=inviter,
            groups=groups,
            source=source,
            template_variables=template_variables,
            metadata=metadata,
        )

        response = self._vortex_api_request_sync(
            "POST", "/invitations", data=request.model_dump(by_alias=True, exclude_none=True)
        )
        return CreateInvitationResponse(**response)

    async def get_autojoin_domains(
        self, scope_type: str, scope: str
    ) -> AutojoinDomainsResponse:
        """
        Get autojoin domains configured for a specific scope

        Args:
            scope_type: The type of scope (e.g., "organization", "team", "project")
            scope: The scope identifier (customer's group ID)

        Returns:
            AutojoinDomainsResponse with autojoin_domains and associated invitation

        Example:
            result = await vortex.get_autojoin_domains("organization", "acme-org")
            print(result.autojoin_domains)  # [AutojoinDomain(id='...', domain='acme.com')]
        """
        from urllib.parse import quote

        response = await self._vortex_api_request(
            "GET",
            f"/invitations/by-scope/{quote(scope_type, safe='')}/{quote(scope, safe='')}/autojoin",
        )
        return AutojoinDomainsResponse(**response)

    def get_autojoin_domains_sync(
        self, scope_type: str, scope: str
    ) -> AutojoinDomainsResponse:
        """
        Get autojoin domains configured for a specific scope (synchronous)

        Args:
            scope_type: The type of scope (e.g., "organization", "team", "project")
            scope: The scope identifier (customer's group ID)

        Returns:
            AutojoinDomainsResponse with autojoin_domains and associated invitation

        Example:
            result = vortex.get_autojoin_domains_sync("organization", "acme-org")
            print(result.autojoin_domains)  # [AutojoinDomain(id='...', domain='acme.com')]
        """
        from urllib.parse import quote

        response = self._vortex_api_request_sync(
            "GET",
            f"/invitations/by-scope/{quote(scope_type, safe='')}/{quote(scope, safe='')}/autojoin",
        )
        return AutojoinDomainsResponse(**response)

    async def configure_autojoin(
        self,
        scope: str,
        scope_type: str,
        domains: List[str],
        widget_id: str,
        scope_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AutojoinDomainsResponse:
        """
        Configure autojoin domains for a specific scope

        This endpoint syncs autojoin domains - it will add new domains, remove domains
        not in the provided list, and deactivate the autojoin invitation if all domains
        are removed (empty array).

        Args:
            scope: The scope identifier (customer's group ID)
            scope_type: The type of scope (e.g., "organization", "team")
            domains: Array of domains to configure for autojoin
            widget_id: The widget configuration ID
            scope_name: Optional display name for the scope
            metadata: Optional metadata to attach to the invitation

        Returns:
            AutojoinDomainsResponse with updated autojoin_domains and associated invitation

        Example:
            result = await vortex.configure_autojoin(
                scope="acme-org",
                scope_type="organization",
                domains=["acme.com", "acme.org"],
                widget_id="widget-123",
                scope_name="Acme Corporation",
            )
        """
        request = ConfigureAutojoinRequest(
            scope=scope,
            scope_type=scope_type,
            domains=domains,
            widget_id=widget_id,
            scope_name=scope_name,
            metadata=metadata,
        )

        response = await self._vortex_api_request(
            "POST",
            "/invitations/autojoin",
            data=request.model_dump(by_alias=True, exclude_none=True),
        )
        return AutojoinDomainsResponse(**response)

    def configure_autojoin_sync(
        self,
        scope: str,
        scope_type: str,
        domains: List[str],
        widget_id: str,
        scope_name: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AutojoinDomainsResponse:
        """
        Configure autojoin domains for a specific scope (synchronous)

        This endpoint syncs autojoin domains - it will add new domains, remove domains
        not in the provided list, and deactivate the autojoin invitation if all domains
        are removed (empty array).

        Args:
            scope: The scope identifier (customer's group ID)
            scope_type: The type of scope (e.g., "organization", "team")
            domains: Array of domains to configure for autojoin
            widget_id: The widget configuration ID
            scope_name: Optional display name for the scope
            metadata: Optional metadata to attach to the invitation

        Returns:
            AutojoinDomainsResponse with updated autojoin_domains and associated invitation

        Example:
            result = vortex.configure_autojoin_sync(
                scope="acme-org",
                scope_type="organization",
                domains=["acme.com", "acme.org"],
                widget_id="widget-123",
                scope_name="Acme Corporation",
            )
        """
        request = ConfigureAutojoinRequest(
            scope=scope,
            scope_type=scope_type,
            domains=domains,
            widget_id=widget_id,
            scope_name=scope_name,
            metadata=metadata,
        )

        response = self._vortex_api_request_sync(
            "POST",
            "/invitations/autojoin",
            data=request.model_dump(by_alias=True, exclude_none=True),
        )
        return AutojoinDomainsResponse(**response)

    async def sync_internal_invitation(
        self,
        creator_id: str,
        target_value: str,
        action: str,
        component_id: str,
    ) -> SyncInternalInvitationResponse:
        """
        Sync an internal invitation action (accept or decline)

        This method notifies Vortex that an internal invitation was accepted or declined
        within your application, so Vortex can update the invitation status accordingly.

        Args:
            creator_id: The inviter's user ID
            target_value: The invitee's user ID
            action: The action taken: "accepted" or "declined"
            component_id: The widget component UUID

        Returns:
            SyncInternalInvitationResponse with processed count and invitation_ids

        Example:
            result = await vortex.sync_internal_invitation(
                creator_id="user-123",
                target_value="user-456",
                action="accepted",
                component_id="component-uuid-789",
            )
            print(f"Processed {result.processed} invitations")
        """
        request = SyncInternalInvitationRequest(
            creator_id=creator_id,
            target_value=target_value,
            action=action,
            component_id=component_id,
        )

        response = await self._vortex_api_request(
            "POST",
            "/invitation-actions/sync-internal-invitation",
            data=request.model_dump(by_alias=True),
        )
        return SyncInternalInvitationResponse(**response)

    def sync_internal_invitation_sync(
        self,
        creator_id: str,
        target_value: str,
        action: str,
        component_id: str,
    ) -> SyncInternalInvitationResponse:
        """
        Sync an internal invitation action (accept or decline) (synchronous)

        See sync_internal_invitation() for full documentation.

        Example:
            result = vortex.sync_internal_invitation_sync(
                creator_id="user-123",
                target_value="user-456",
                action="accepted",
                component_id="component-uuid-789",
            )
        """
        request = SyncInternalInvitationRequest(
            creator_id=creator_id,
            target_value=target_value,
            action=action,
            component_id=component_id,
        )

        response = self._vortex_api_request_sync(
            "POST",
            "/invitation-actions/sync-internal-invitation",
            data=request.model_dump(by_alias=True),
        )
        return SyncInternalInvitationResponse(**response)

    async def close(self) -> None:
        """Close the HTTP client"""
        await self._client.aclose()

    def close_sync(self) -> None:
        """Close the synchronous HTTP client"""
        self._sync_client.close()

    async def __aenter__(self) -> "Vortex":
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit"""
        await self.close()

    def __enter__(self) -> "Vortex":
        """Context manager entry"""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit"""
        self.close_sync()
