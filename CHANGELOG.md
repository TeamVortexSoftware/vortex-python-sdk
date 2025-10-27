# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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