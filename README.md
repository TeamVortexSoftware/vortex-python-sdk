# Vortex Python SDK

A Python SDK for Vortex invitation management and JWT generation.

## Features

### Invitation Delivery Types

Vortex supports multiple delivery methods for invitations:

- **`email`** - Email invitations sent by Vortex (includes reminders and nudges)
- **`phone`** - Phone invitations sent by the user/customer
- **`share`** - Shareable invitation links for social sharing
- **`internal`** - Internal invitations managed entirely by your application
  - No email/SMS communication triggered by Vortex
  - Target value can be any customer-defined identifier
  - Useful for in-app invitation flows where you handle the delivery
  - Example use case: In-app notifications, dashboard invites, etc.

## Installation

```bash
pip install vortex-python-sdk
```

> **Note**: The package will be available on PyPI once published. See [PUBLISHING.md](PUBLISHING.md) for publishing instructions.

## Usage

### Basic Setup

```python
from vortex_sdk import Vortex

# Initialize the client with your Vortex API key
vortex = Vortex(api_key="your-vortex-api-key")

# Or with custom base URL
vortex = Vortex(api_key="your-vortex-api-key", base_url="https://custom-api.example.com")
```

### JWT Generation

```python
# Generate JWT for a user
user = {
    "id": "user-123",
    "email": "user@example.com",
    "user_name": "Jane Doe",                                    # Optional: user's display name
    "user_avatar_url": "https://example.com/avatars/jane.jpg",  # Optional: user's avatar URL
    "admin_scopes": ["autojoin"]                                # Optional: grants autojoin admin privileges
}

jwt = vortex.generate_jwt(user=user)
print(f"JWT: {jwt}")

# Or using type-safe models
from vortex_sdk import User

user = User(
    id="user-123",
    email="user@example.com",
    user_name="Jane Doe",                                       # Optional
    user_avatar_url="https://example.com/avatars/jane.jpg",     # Optional
    admin_scopes=["autojoin"]                              # Optional
)

jwt = vortex.generate_jwt(user=user)
```

### Invitation Management

#### Get Invitations by Target

```python
import asyncio

async def get_user_invitations():
    # Async version
    invitations = await vortex.get_invitations_by_target("email", "user@example.com")
    for invitation in invitations:
        print(f"Invitation ID: {invitation.id}, Status: {invitation.status}")

# Sync version
invitations = vortex.get_invitations_by_target_sync("email", "user@example.com")
```

#### Accept an Invitation

```python
async def accept_user_invitation():
    # Async version
    result = await vortex.accept_invitation(
        invitation_id="inv-123",
        user={"email": "user@example.com"}
    )
    print(f"Result: {result}")

# Sync version
result = vortex.accept_invitation_sync(
    invitation_id="inv-123",
    user={"email": "user@example.com"}
)
```

#### Get Specific Invitation

```python
async def get_invitation():
    # Async version
    invitation = await vortex.get_invitation("invitation-id")
    print(f"Invitation: {invitation.id}")

# Sync version
invitation = vortex.get_invitation_sync("invitation-id")
```

#### Revoke Invitation

```python
async def revoke_invitation():
    # Async version
    result = await vortex.revoke_invitation("invitation-id")
    print(f"Revoked: {result}")

# Sync version
result = vortex.revoke_invitation_sync("invitation-id")
```

### Group Operations

#### Get Invitations by Group

```python
async def get_group_invitations():
    # Async version
    invitations = await vortex.get_invitations_by_group("organization", "org123")
    print(f"Found {len(invitations)} invitations")

# Sync version
invitations = vortex.get_invitations_by_group_sync("organization", "org123")
```

#### Delete Invitations by Group

```python
async def delete_group_invitations():
    # Async version
    result = await vortex.delete_invitations_by_group("organization", "org123")
    print(f"Deleted: {result}")

# Sync version
result = vortex.delete_invitations_by_group_sync("organization", "org123")
```

#### Reinvite

```python
async def reinvite_user():
    # Async version
    invitation = await vortex.reinvite("invitation-id")
    print(f"Reinvited: {invitation.id}")

# Sync version
invitation = vortex.reinvite_sync("invitation-id")
```

#### Sync Internal Invitation

If you're using `internal` delivery type invitations and managing the invitation flow within your own application, you can sync invitation decisions back to Vortex when users accept or decline invitations in your system.

```python
async def sync_internal_invitation_action():
    # Async version
    result = await vortex.sync_internal_invitation(
        creator_id="user-123",      # The inviter's user ID in your system
        target_value="user-456",    # The invitee's user ID in your system
        action="accepted",          # "accepted" or "declined"
        component_id="component-uuid"  # The widget component UUID
    )
    print(f"Processed: {result['processed']}")
    print(f"Invitation IDs: {result['invitationIds']}")

# Sync version
result = vortex.sync_internal_invitation_sync(
    creator_id="user-123",
    target_value="user-456",
    action="accepted",
    component_id="component-uuid"
)
```

**Parameters:**
- `creator_id` (str) — The inviter's user ID in your system
- `target_value` (str) — The invitee's user ID in your system
- `action` ("accepted" | "declined") — The invitation decision
- `component_id` (str) — The widget component UUID

**Response:**
- `processed` (int) — Count of invitations processed
- `invitationIds` (list[str]) — IDs of processed invitations

**Use cases:**
- You handle invitation delivery through your own in-app notifications or UI
- Users accept/decline invitations within your application
- You need to keep Vortex updated with the invitation status

### Context Manager Usage

```python
# Async context manager
async with Vortex(api_key="your-api-key") as vortex:
    invitations = await vortex.get_invitations_by_target("email", "user@example.com")

# Sync context manager
with Vortex(api_key="your-api-key") as vortex:
    invitations = vortex.get_invitations_by_target_sync("email", "user@example.com")
```

### Error Handling

```python
from vortex_sdk import VortexApiError

try:
    invitation = vortex.get_invitation_sync("invalid-id")
except VortexApiError as e:
    print(f"API Error: {e.message} (Status: {e.status_code})")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Development

### Installation

```bash
# Install development dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
# Format code
black src/ tests/
isort src/ tests/

# Lint code
ruff check src/ tests/
mypy src/
```

## Webhooks

The SDK provides built-in support for verifying and parsing incoming webhook events from Vortex.

### Setup

```python
import os
from vortex_sdk import VortexWebhooks, is_webhook_event, is_analytics_event

webhooks = VortexWebhooks(secret=os.environ["VORTEX_WEBHOOK_SECRET"])
```

### Verifying and Parsing Events

```python
# In your HTTP handler (Flask example):
@app.route("/webhooks/vortex", methods=["POST"])
def handle_webhook():
    payload = request.get_data(as_text=True)
    signature = request.headers.get("X-Vortex-Signature", "")

    try:
        event = webhooks.construct_event(payload, signature)
    except VortexWebhookSignatureError:
        return "Invalid signature", 400

    if is_webhook_event(event.__dict__):
        print(f"Webhook event: {event.type}")
    elif is_analytics_event(event.__dict__):
        print(f"Analytics event: {event.name}")

    return "OK", 200
```

### Event Types

Webhook event types are available as the `WebhookEventType` enum:

```python
from vortex_sdk import WebhookEventType

if event.type == WebhookEventType.INVITATION_ACCEPTED:
    # Handle invitation accepted
    pass
```

## License

MIT
