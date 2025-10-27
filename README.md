# Vortex Python SDK

A Python SDK for Vortex invitation management and JWT generation.

## Installation

```bash
pip install vortex-python-sdk
```

> **Note**: The package will be available on PyPI once published. See [PUBLISHING.md](PUBLISHING.md) for publishing instructions.

## Usage

### Basic Setup

```python
from vortex_sdk import Vortex

# Initialize the client
vortex = Vortex(api_key="your-api-key")

# Or with custom base URL
vortex = Vortex(api_key="your-api-key", base_url="https://custom-api.example.com")
```

### JWT Generation

```python
# Generate JWT for a user
jwt = vortex.generate_jwt({
    "user_id": "user123",
    "identifiers": {
        "email": "user@example.com",
        "username": "johndoe"
    },
    "groups": ["admin", "users"],
    "role": "admin"
})

print(f"JWT: {jwt}")
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

#### Accept Invitations

```python
async def accept_user_invitations():
    # Async version
    result = await vortex.accept_invitations(
        invitation_ids=["inv1", "inv2"],
        target={"type": "email", "value": "user@example.com"}
    )
    print(f"Result: {result}")

# Sync version
result = vortex.accept_invitations_sync(
    invitation_ids=["inv1", "inv2"],
    target={"type": "email", "value": "user@example.com"}
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

## License

MIT