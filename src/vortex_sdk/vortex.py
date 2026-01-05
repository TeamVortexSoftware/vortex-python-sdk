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
    Invitation,
    InvitationTarget,
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
            user: User object or dict with 'id', 'email', and optional 'admin_scopes'
            **extra: Additional properties to include in JWT payload

        Returns:
            JWT token string

        Raises:
            ValueError: If API key format is invalid or required fields are missing

        Example:
            user = {'id': 'user-123', 'email': 'user@example.com', 'admin_scopes': ['autojoin']}
            jwt = vortex.generate_jwt(user=user)

            # With additional properties
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

        # Add adminScopes if present
        if user.admin_scopes:
            jwt_payload["adminScopes"] = user.admin_scopes

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
            elif target_type in ("sms", "phoneNumber"):
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
            elif target_type in ("sms", "phoneNumber"):
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
