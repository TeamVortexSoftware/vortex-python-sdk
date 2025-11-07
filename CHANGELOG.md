# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.5] - 2025-11-06

### Fixed

- **CRITICAL FIX**: Updated api url & auth headers

## [0.0.3] - 2025-01-31

### Fixed

- **CRITICAL FIX**: JWT generation now matches Node.js SDK implementation exactly
  - Improved JWT signing algorithm to match Node.js SDK
  - Added `iat` (issued at) and `expires` timestamp fields to JWT
  - Added `attributes` field support in JwtPayload for custom user attributes
  - Fixed base64url encoding
- Added comprehensive tests verifying JWT output matches Node.js SDK byte-for-byte

### Breaking Changes

- JWT structure changed significantly - tokens from 0.0.2 are incompatible with 0.0.3
- JWTs now include `iat` and `expires` fields for proper token lifecycle management

## [0.0.2] - 2025-01-31

### Fixed

- **BREAKING FIX**: JWT payload format now matches TypeScript SDK
  - `identifiers` changed from `Dict[str, str]` to `List[Dict]` with `type` and `value` fields
  - `groups` structure now properly includes `type`, `id`/`groupId`, and `name` fields
  - Added `IdentifierInput` type for type-safe identifier creation
  - Updated `GroupInput` to support both `id` (legacy) and `groupId` (preferred) with proper camelCase serialization
- Updated documentation with correct JWT generation examples

### Migration Guide

If you're upgrading from 0.0.1, update your JWT generation code:

**Before (0.0.1):**

```python
jwt = vortex.generate_jwt({
    "user_id": "user-123",
    "identifiers": {"email": "user@example.com"},  # Dict
    "groups": ["admin"],  # List of strings
})
```

**After (0.0.2):**

```python
jwt = vortex.generate_jwt({
    "user_id": "user-123",
    "identifiers": [{"type": "email", "value": "user@example.com"}],  # List of dicts
    "groups": [{"type": "team", "id": "team-1", "name": "Engineering"}],  # List of objects
})
```

## [0.0.1] - 2024-10-10

### Added

- Initial release of Vortex Python SDK
- JWT generation with HMAC-SHA256 signing
- Complete invitation management API
- Async and sync HTTP client methods
- Type safety with Pydantic models
- Context manager support for resource cleanup
- Comprehensive error handling with VortexApiError
- Full compatibility with Node.js SDK API

### Features

- `generate_jwt()` - Generate Vortex JWT tokens
- `get_invitations_by_target()` - Get invitations by email/username/phone
- `accept_invitations()` - Accept multiple invitations
- `get_invitation()` - Get specific invitation by ID
- `revoke_invitation()` - Revoke invitation
- `get_invitations_by_group()` - Get invitations for a group
- `delete_invitations_by_group()` - Delete all group invitations
- `reinvite()` - Reinvite functionality
- Both async and sync versions of all methods
- Python 3.8+ support
