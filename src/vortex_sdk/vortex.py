import json
import hmac
import hashlib
import base64
from typing import Dict, List, Optional, Union, Literal
from urllib.parse import urlencode
import httpx
from .types import (
    JwtPayload,
    InvitationTarget,
    Invitation,
    CreateInvitationRequest,
    AcceptInvitationsRequest,
    ApiResponse,
    VortexApiError
)


class Vortex:
    def __init__(self, api_key: str, base_url: str = "https://api.vortexsoftware.com"):
        """
        Initialize Vortex client

        Args:
            api_key: Your Vortex API key
            base_url: Base URL for Vortex API (default: https://api.vortexsoftware.com)
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self._client = httpx.AsyncClient()
        self._sync_client = httpx.Client()

    def generate_jwt(self, payload: Union[JwtPayload, Dict]) -> str:
        """
        Generate a JWT token for the given payload

        Args:
            payload: JWT payload containing user_id, identifiers, groups, and role

        Returns:
            JWT token string
        """
        if isinstance(payload, dict):
            payload = JwtPayload(**payload)

        # JWT Header
        header = {
            "alg": "HS256",
            "typ": "JWT"
        }

        # JWT Payload
        jwt_payload = {
            "userId": payload.user_id,
            "identifiers": payload.identifiers,
        }

        if payload.groups is not None:
            jwt_payload["groups"] = payload.groups
        if payload.role is not None:
            jwt_payload["role"] = payload.role

        # Encode header and payload
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(jwt_payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')

        # Create signature
        message = f"{header_encoded}.{payload_encoded}"
        signature = hmac.new(
            self.api_key.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()

        signature_encoded = base64.urlsafe_b64encode(signature).decode().rstrip('=')

        return f"{message}.{signature_encoded}"

    async def _vortex_api_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
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
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "vortex-python-sdk/0.0.1"
        }

        try:
            response = await self._client.request(
                method=method,
                url=url,
                json=data,
                params=params,
                headers=headers
            )

            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', f'API request failed with status {response.status_code}')
                except:
                    error_message = f'API request failed with status {response.status_code}'

                raise VortexApiError(error_message, response.status_code)

            return response.json()

        except httpx.RequestError as e:
            raise VortexApiError(f"Request failed: {str(e)}")

    def _vortex_api_request_sync(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
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
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "vortex-python-sdk/0.0.1"
        }

        try:
            response = self._sync_client.request(
                method=method,
                url=url,
                json=data,
                params=params,
                headers=headers
            )

            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    error_message = error_data.get('error', f'API request failed with status {response.status_code}')
                except:
                    error_message = f'API request failed with status {response.status_code}'

                raise VortexApiError(error_message, response.status_code)

            return response.json()

        except httpx.RequestError as e:
            raise VortexApiError(f"Request failed: {str(e)}")

    async def get_invitations_by_target(
        self,
        target_type: Literal["email", "username", "phoneNumber"],
        target_value: str
    ) -> List[Invitation]:
        """
        Get invitations for a specific target

        Args:
            target_type: Type of target (email, username, or phoneNumber)
            target_value: Target value

        Returns:
            List of invitations
        """
        params = {
            "targetType": target_type,
            "targetValue": target_value
        }

        response = await self._vortex_api_request("GET", "/invitations/by-target", params=params)
        return [Invitation(**inv) for inv in response.get("invitations", [])]

    def get_invitations_by_target_sync(
        self,
        target_type: Literal["email", "username", "phoneNumber"],
        target_value: str
    ) -> List[Invitation]:
        """
        Get invitations for a specific target (synchronous)

        Args:
            target_type: Type of target (email, username, or phoneNumber)
            target_value: Target value

        Returns:
            List of invitations
        """
        params = {
            "targetType": target_type,
            "targetValue": target_value
        }

        response = self._vortex_api_request_sync("GET", "/invitations/by-target", params=params)
        return [Invitation(**inv) for inv in response.get("invitations", [])]

    async def get_invitation(self, invitation_id: str) -> Invitation:
        """
        Get a specific invitation by ID

        Args:
            invitation_id: Invitation ID

        Returns:
            Invitation object
        """
        response = await self._vortex_api_request("GET", f"/invitations/{invitation_id}")
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
        target: Union[InvitationTarget, Dict[str, str]]
    ) -> Dict:
        """
        Accept multiple invitations

        Args:
            invitation_ids: List of invitation IDs to accept
            target: Target information (type and value)

        Returns:
            API response
        """
        if isinstance(target, dict):
            target = InvitationTarget(**target)

        data = {
            "invitationIds": invitation_ids,
            "target": target.model_dump()
        }

        return await self._vortex_api_request("POST", "/invitations/accept", data=data)

    def accept_invitations_sync(
        self,
        invitation_ids: List[str],
        target: Union[InvitationTarget, Dict[str, str]]
    ) -> Dict:
        """
        Accept multiple invitations (synchronous)

        Args:
            invitation_ids: List of invitation IDs to accept
            target: Target information (type and value)

        Returns:
            API response
        """
        if isinstance(target, dict):
            target = InvitationTarget(**target)

        data = {
            "invitationIds": invitation_ids,
            "target": target.model_dump()
        }

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
        self,
        group_type: str,
        group_id: str
    ) -> List[Invitation]:
        """
        Get invitations for a specific group

        Args:
            group_type: Type of group
            group_id: Group ID

        Returns:
            List of invitations
        """
        response = await self._vortex_api_request("GET", f"/invitations/by-group/{group_type}/{group_id}")
        return [Invitation(**inv) for inv in response.get("invitations", [])]

    def get_invitations_by_group_sync(
        self,
        group_type: str,
        group_id: str
    ) -> List[Invitation]:
        """
        Get invitations for a specific group (synchronous)

        Args:
            group_type: Type of group
            group_id: Group ID

        Returns:
            List of invitations
        """
        response = self._vortex_api_request_sync("GET", f"/invitations/by-group/{group_type}/{group_id}")
        return [Invitation(**inv) for inv in response.get("invitations", [])]

    async def delete_invitations_by_group(
        self,
        group_type: str,
        group_id: str
    ) -> Dict:
        """
        Delete all invitations for a specific group

        Args:
            group_type: Type of group
            group_id: Group ID

        Returns:
            API response
        """
        return await self._vortex_api_request("DELETE", f"/invitations/by-group/{group_type}/{group_id}")

    def delete_invitations_by_group_sync(
        self,
        group_type: str,
        group_id: str
    ) -> Dict:
        """
        Delete all invitations for a specific group (synchronous)

        Args:
            group_type: Type of group
            group_id: Group ID

        Returns:
            API response
        """
        return self._vortex_api_request_sync("DELETE", f"/invitations/by-group/{group_type}/{group_id}")

    async def reinvite(self, invitation_id: str) -> Invitation:
        """
        Reinvite for a specific invitation

        Args:
            invitation_id: Invitation ID to reinvite

        Returns:
            Updated invitation object
        """
        response = await self._vortex_api_request("POST", f"/invitations/{invitation_id}/reinvite")
        return Invitation(**response)

    def reinvite_sync(self, invitation_id: str) -> Invitation:
        """
        Reinvite for a specific invitation (synchronous)

        Args:
            invitation_id: Invitation ID to reinvite

        Returns:
            Updated invitation object
        """
        response = self._vortex_api_request_sync("POST", f"/invitations/{invitation_id}/reinvite")
        return Invitation(**response)

    async def close(self):
        """Close the HTTP client"""
        await self._client.aclose()

    def close_sync(self):
        """Close the synchronous HTTP client"""
        self._sync_client.close()

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close_sync()