"""
Integration test for Vortex Python SDK
Tests the full flow: Create -> Get -> Accept invitation
"""

import os
import time
import pytest
import httpx
from vortex_sdk import Vortex


@pytest.mark.integration
class TestIntegration:
    """Integration tests for Vortex Python SDK"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test environment"""
        # Validate required environment variables
        self.api_key = os.getenv("TEST_INTEGRATION_SDKS_VORTEX_API_KEY")
        if not self.api_key:
            raise ValueError("Missing required environment variable: TEST_INTEGRATION_SDKS_VORTEX_API_KEY")

        self.client_api_url = os.getenv("TEST_INTEGRATION_SDKS_VORTEX_CLIENT_API_URL")
        if not self.client_api_url:
            raise ValueError("Missing required environment variable: TEST_INTEGRATION_SDKS_VORTEX_CLIENT_API_URL")

        self.public_api_url = os.getenv("TEST_INTEGRATION_SDKS_VORTEX_PUBLIC_API_URL")
        if not self.public_api_url:
            raise ValueError("Missing required environment variable: TEST_INTEGRATION_SDKS_VORTEX_PUBLIC_API_URL")

        self.session_id = os.getenv("TEST_INTEGRATION_SDKS_VORTEX_SESSION_ID")
        if not self.session_id:
            raise ValueError("Missing required environment variable: TEST_INTEGRATION_SDKS_VORTEX_SESSION_ID")

        self.create_client = Vortex(self.api_key, base_url=f"{self.client_api_url}/api/v1")
        self.public_client = Vortex(self.api_key, base_url=f"{self.public_api_url}/api/v1")

        timestamp = str(int(time.time()))

        self.test_user_id = os.getenv("TEST_INTEGRATION_SDKS_USER_ID")
        if not self.test_user_id:
            raise ValueError("Missing required environment variable: TEST_INTEGRATION_SDKS_USER_ID")
        self.test_user_id = self.test_user_id.replace("{timestamp}", timestamp)

        self.test_user_email = os.getenv("TEST_INTEGRATION_SDKS_USER_EMAIL")
        if not self.test_user_email:
            raise ValueError("Missing required environment variable: TEST_INTEGRATION_SDKS_USER_EMAIL")
        self.test_user_email = self.test_user_email.replace("{timestamp}", timestamp)

        self.test_group_type = os.getenv("TEST_INTEGRATION_SDKS_GROUP_TYPE")
        if not self.test_group_type:
            raise ValueError("Missing required environment variable: TEST_INTEGRATION_SDKS_GROUP_TYPE")

        self.test_group_name = os.getenv("TEST_INTEGRATION_SDKS_GROUP_NAME")
        if not self.test_group_name:
            raise ValueError("Missing required environment variable: TEST_INTEGRATION_SDKS_GROUP_NAME")

        # TEST_INTEGRATION_SDKS_GROUP_ID is dynamic - generated from timestamp
        self.test_group_id = f"test-group-{os.getpid()}"

        self.invitation_id = None

    @pytest.mark.asyncio
    async def test_full_invitation_flow(self):
        """Test the complete invitation flow"""
        print("\n--- Starting Python SDK Integration Test ---")

        # Step 1: Create invitation
        print("Step 1: Creating invitation...")
        self.invitation_id = await self.create_invitation()
        assert self.invitation_id is not None, "Failed to create invitation"
        print(f"✓ Created invitation: {self.invitation_id}")

        # Step 2a: Get invitation by ID
        print("Step 2a: Getting invitation by ID...")
        invitation = await self.get_invitation_by_id()
        assert invitation is not None, "Failed to get invitation by ID"
        assert invitation.id == self.invitation_id
        print("✓ Retrieved invitation by ID successfully")

        # Step 2b: Get invitations by target
        print("Step 2b: Getting invitations by target...")
        invitations = await self.get_invitations_by_target()
        assert invitations is not None and len(invitations) > 0, "Failed to get invitations by target"
        # Verify the single invitation is in the list
        found_in_list = any(inv.id == self.invitation_id for inv in invitations)
        assert found_in_list, "Invitation not found in list returned by target"
        print("✓ Retrieved invitations by target successfully and verified invitation is in list")

        # Step 3: Accept invitation
        print("Step 3: Accepting invitation...")
        result = await self.accept_invitation()
        assert result is not None, "Failed to accept invitation"
        print("✓ Accepted invitation successfully")

        print("--- Python SDK Integration Test Complete ---\n")

    async def create_invitation(self) -> str | None:
        """Create a test invitation using the create API"""
        # Generate JWT for authentication
        jwt = self.create_client.generate_jwt(
            user={
                "id": self.test_user_id,
                "email": self.test_user_email
            },
        )

        # Step 1: Fetch widget configuration to get the widget configuration ID and sessionAttestation
        component_id = os.getenv("TEST_INTEGRATION_SDKS_VORTEX_COMPONENT_ID")
        if not component_id:
            raise ValueError("Missing required environment variable: TEST_INTEGRATION_SDKS_VORTEX_COMPONENT_ID")
        widget_url = f"{self.client_api_url}/api/v1/widgets/{component_id}?templateVariables=lzstr:N4Ig5gTg9grgDgfQHYEMC2BTEAuEBlAEQGkACAFQwGcAXEgcWnhABoQBLJANzeowmXRZcBCCQBqUCLwAeLcI0SY0AIz4IAxrCTUcIAMxzNaOCiQBPAZl0SpGaSQCSSdQDoQAXyA"

        async with httpx.AsyncClient() as client:
            # Initial widget request without session attestation
            widget_response = await client.get(
                widget_url,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {jwt}",
                    "x-session-id": self.session_id
                }
            )

            if widget_response.status_code != 200:
                print(f"Failed to fetch widget configuration with HTTP {widget_response.status_code}: {widget_response.text}")
                return None

            widget_data = widget_response.json()
            widget_config_id = widget_data.get("data", {}).get("widgetConfiguration", {}).get("id")
            session_attestation = widget_data.get("data", {}).get("sessionAttestation")

            if not widget_config_id:
                print("Widget configuration ID not found in response")
                return None

            if not session_attestation:
                print("Session attestation not found in widget response")
                return None

            print(f"Using widget configuration ID: {widget_config_id}")
            print(f"Received sessionAttestation from widget")

            # Now use the session attestation for subsequent requests
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {jwt}",
                "x-session-id": self.session_id,
                "x-session-attestation": session_attestation
            }

            # Step 2: Create invitation with the widget configuration ID
            invitation_url = f"{self.client_api_url}/api/v1/invitations"

            data = {
                "payload": {
                    "emails": {
                        "value": self.test_user_email,
                        "type": "email",
                        "role": "member"
                    }
                },
                "group": {
                    "type": self.test_group_type,
                    "groupId": self.test_group_id,
                    "name": self.test_group_name
                },
                "source": "email",
                "widgetConfigurationId": widget_config_id,
                "templateVariables": {
                    "group_name": "SDK Test Group",
                    "inviter_name": "Dr Vortex",
                    "group_member_count": "3",
                    "company_name": "Vortex Inc."
                }
            }

            response = await client.post(invitation_url, json=data, headers=headers)

            if response.status_code not in [200, 201]:
                print(f"Create invitation failed with HTTP {response.status_code}: {response.text}")
                return None

            result = response.json()
            # The API returns the full widget configuration with invitation entries
            invitation_id = result.get("data", {}).get("invitationEntries", [{}])[0].get("id") or result.get("id")

            if invitation_id:
                print(f"Successfully extracted invitation ID: {invitation_id}")

            return invitation_id

    async def get_invitation_by_id(self) -> dict | None:
        """Get the invitation by ID using the public API"""
        invitation = await self.public_client.get_invitation(self.invitation_id)
        return invitation

    async def get_invitations_by_target(self) -> list | None:
        """Get invitations by target using the public API"""
        invitations = await self.public_client.get_invitations_by_target(
            "email",
            self.test_user_email
        )
        return invitations

    async def accept_invitation(self) -> dict | None:
        """Accept the invitation using the public API"""
        result = await self.public_client.accept_invitations(
            [self.invitation_id],
            {
                "type": "email",
                "value": self.test_user_email
            }
        )

        return result
