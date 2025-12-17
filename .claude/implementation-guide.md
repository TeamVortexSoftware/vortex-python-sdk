# Vortex Python SDK Integration Guide

## SDK Information

**Package**: `vortex-python-sdk`
**Type**: Base SDK (Core library for Python applications)
**Framework**: Framework-agnostic Python 3.8+
**Integration Style**: Client-based with async/sync support

This SDK provides the core `Vortex` class for Python applications. It works with:
- **FastAPI** - Modern async web framework
- **Flask** - Popular micro web framework
- **Django** - Full-featured web framework
- **Starlette** - Lightweight ASGI framework
- **Plain Python** - Standalone scripts or custom frameworks
- **Any Python framework** - Framework-agnostic design

**Key Features**:
- **Dual async/sync API**: Every method has both async and sync versions
- **Type-safe**: Full Pydantic models with type hints
- **Context managers**: Built-in support for proper resource cleanup
- **httpx-based**: Modern HTTP client with connection pooling

---

## Expected Input Context

When this guide is invoked by the orchestrator, expect:

### Integration Contract
```typescript
{
  backend: {
    framework: 'python',
    packageManager: 'pip' | 'poetry' | 'pipenv',
    pythonVersion: string,  // e.g., '3.9', '3.10', '3.11'
    frameworkDetails?: {
      name?: 'fastapi' | 'flask' | 'django' | 'starlette' | 'custom',
      version?: string,
      isAsync?: boolean
    }
  }
}
```

### Discovery Data
```typescript
{
  projectRoot: string,
  existingFiles: string[],  // requirements.txt, pyproject.toml, main.py, etc.
  hasPyprojectToml: boolean,
  hasRequirementsTxt: boolean,
  frameworkName?: string,
  isAsyncFramework?: boolean
}
```

---

## Implementation Overview

The Python SDK provides the core `Vortex` class for:
1. **JWT Generation**: Generate JWTs for authenticated users with custom attributes
2. **Invitation Management**: Query, accept, revoke, and manage invitations
3. **Async/Sync Support**: Every method available in both async and sync versions
4. **Type Safety**: Pydantic models for request/response validation

Integration involves:
1. Installing the SDK via pip/poetry/pipenv
2. Creating a `Vortex` client instance with your API key
3. Implementing HTTP endpoints/routes that call Vortex methods
4. Extracting authenticated user from your auth system
5. **Critical**: Implementing custom database logic for accepting invitations

---

## Critical SDK Specifics

### 1. Client Instantiation
```python
from vortex_sdk import Vortex

vortex = Vortex(
    api_key="your-api-key",
    base_url="https://api.vortexsoftware.com/api/v1"  # Optional: custom base URL
)
```

### 2. JWT Generation - Current Format (Recommended)
```python
from vortex_sdk import User

user = User(
    id="user-123",
    email="user@example.com",
    admin_scopes=["autojoin"]  # Optional: grant admin capabilities
)

jwt = vortex.generate_jwt(user=user)

# Or with dict
user_dict = {
    "id": "user-123",
    "email": "user@example.com",
    "admin_scopes": ["autojoin"]
}

jwt = vortex.generate_jwt(user=user_dict)
```

### 3. JWT Generation with Additional Properties
```python
user = User(id="user-123", email="user@example.com")

jwt = vortex.generate_jwt(
    user=user,
    componentId="optional-component-id",
    scope="optional-scope",
    scopeType="optional-scope-type"
)
```

### 4. Async vs Sync Methods
```python
# Async methods (for FastAPI, Starlette, async frameworks)
invitations = await vortex.get_invitations_by_target("email", "user@example.com")
invitation = await vortex.get_invitation("invitation-id")
await vortex.revoke_invitation("invitation-id")

# Sync methods (for Flask, Django, sync frameworks)
invitations = vortex.get_invitations_by_target_sync("email", "user@example.com")
invitation = vortex.get_invitation_sync("invitation-id")
vortex.revoke_invitation_sync("invitation-id")
```

### 5. Context Manager Usage
```python
# Async context manager
async with Vortex(api_key="your-api-key") as vortex:
    invitations = await vortex.get_invitations_by_target("email", "user@example.com")

# Sync context manager
with Vortex(api_key="your-api-key") as vortex:
    invitations = vortex.get_invitations_by_target_sync("email", "user@example.com")
```

### 6. Accept Invitations - REQUIRES DATABASE OVERRIDE
```python
# This SDK method just marks invitations as accepted in Vortex
# YOU MUST implement database logic to actually add user to groups
result = await vortex.accept_invitations(
    invitation_ids=["inv-1", "inv-2"],
    target={"type": "email", "value": "user@example.com"}
)

# After calling this, you MUST implement your own database logic:
# - Add user to teams/organizations
# - Grant permissions/roles
# - Create user records if needed
# - Update user metadata
```

---

## Step-by-Step Implementation

### Step 1: Install Package

**Option A: pip**:
```bash
pip install vortex-python-sdk
```

**Option B: Poetry**:
```bash
poetry add vortex-python-sdk
```

**Option C: Pipenv**:
```bash
pipenv install vortex-python-sdk
```

**Option D: requirements.txt**:
```txt
vortex-python-sdk>=0.1.0
```

### Step 2: Set Environment Variables

Add to `.env`:
```bash
VORTEX_API_KEY=your_api_key_here
```

Load in Python:
```python
# Option 1: python-dotenv
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv("VORTEX_API_KEY")

# Option 2: Direct environment variable
import os
api_key = os.environ["VORTEX_API_KEY"]
```

### Step 3: Create Vortex Client Helper

**Option A: Singleton Pattern** (`app/lib/vortex_client.py`):
```python
import os
from vortex_sdk import Vortex
from typing import Optional

_vortex_instance: Optional[Vortex] = None

def get_vortex_client() -> Vortex:
    """Get or create Vortex client instance"""
    global _vortex_instance

    if _vortex_instance is None:
        api_key = os.getenv("VORTEX_API_KEY")
        if not api_key:
            raise ValueError("VORTEX_API_KEY environment variable is required")

        _vortex_instance = Vortex(api_key=api_key)

    return _vortex_instance
```

**Option B: FastAPI Dependency** (`app/dependencies.py`):
```python
import os
from vortex_sdk import Vortex
from fastapi import Depends
from typing import Annotated

def get_vortex_client() -> Vortex:
    """Dependency to get Vortex client"""
    api_key = os.getenv("VORTEX_API_KEY")
    if not api_key:
        raise ValueError("VORTEX_API_KEY is not configured")

    return Vortex(api_key=api_key)

VortexDep = Annotated[Vortex, Depends(get_vortex_client)]
```

**Option C: Django Settings**:
```python
# settings.py
VORTEX_API_KEY = os.environ.get("VORTEX_API_KEY")

# app/utils/vortex.py
from django.conf import settings
from vortex_sdk import Vortex

def get_vortex_client() -> Vortex:
    """Get Vortex client configured from Django settings"""
    if not settings.VORTEX_API_KEY:
        raise ValueError("VORTEX_API_KEY not configured in settings")

    return Vortex(api_key=settings.VORTEX_API_KEY)
```

**Option D: Flask Extension** (`app/extensions.py`):
```python
from flask import current_app
from vortex_sdk import Vortex

def get_vortex_client() -> Vortex:
    """Get Vortex client from Flask app config"""
    api_key = current_app.config.get("VORTEX_API_KEY")
    if not api_key:
        raise ValueError("VORTEX_API_KEY not configured")

    return Vortex(api_key=api_key)
```

### Step 4: Extract Authenticated User

Create helper functions to extract user from your auth system:

**FastAPI Example**:
```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Annotated, Optional
from vortex_sdk import User

security = HTTPBearer()

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]
) -> dict:
    """Extract user from JWT token"""
    token = credentials.credentials

    # Decode your JWT token (use your auth library)
    try:
        payload = decode_jwt(token)  # Your JWT decode logic
        return {
            "id": payload["user_id"],
            "email": payload["email"],
            "is_admin": payload.get("role") == "admin"
        }
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid authentication credentials", "code": "UNAUTHORIZED"}
        )

def to_vortex_user(user: dict) -> User:
    """Convert app user to Vortex user format"""
    return User(
        id=str(user["id"]),
        email=user["email"],
        admin_scopes=["autojoin"] if user.get("is_admin") else None
    )

CurrentUser = Annotated[dict, Depends(get_current_user)]
```

**Flask Example**:
```python
from flask import g, request
from functools import wraps
from typing import Optional
from vortex_sdk import User

def get_current_user() -> Optional[dict]:
    """Get current user from session or JWT"""
    # Option 1: Session-based
    from flask import session
    if "user_id" in session:
        return {
            "id": session["user_id"],
            "email": session["user_email"],
            "is_admin": session.get("is_admin", False)
        }

    # Option 2: JWT-based
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = decode_jwt(token)  # Your JWT decode logic
        return {
            "id": payload["user_id"],
            "email": payload["email"],
            "is_admin": payload.get("role") == "admin"
        }

    return None

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            return {"error": "Unauthorized", "code": "UNAUTHORIZED"}, 401
        g.user = user
        return f(*args, **kwargs)
    return decorated_function

def to_vortex_user(user: dict) -> User:
    """Convert app user to Vortex user format"""
    return User(
        id=str(user["id"]),
        email=user["email"],
        admin_scopes=["autojoin"] if user.get("is_admin") else None
    )
```

**Django Example**:
```python
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from typing import Optional
from vortex_sdk import User

def get_current_user(request) -> Optional[dict]:
    """Get current user from Django request"""
    if request.user.is_authenticated:
        return {
            "id": str(request.user.id),
            "email": request.user.email,
            "is_admin": request.user.is_staff or request.user.is_superuser
        }
    return None

def to_vortex_user(user: dict) -> User:
    """Convert Django user to Vortex user format"""
    return User(
        id=user["id"],
        email=user["email"],
        admin_scopes=["autojoin"] if user.get("is_admin") else None
    )
```

### Step 5: Implement JWT Generation Endpoint

**FastAPI Example** (`app/routers/vortex.py`):
```python
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import Optional
from vortex_sdk import VortexApiError

router = APIRouter(prefix="/api/vortex", tags=["vortex"])

class JwtRequest(BaseModel):
    componentId: Optional[str] = None
    scope: Optional[str] = None
    scopeType: Optional[str] = None

class JwtResponse(BaseModel):
    jwt: str

@router.post("/jwt", response_model=JwtResponse)
async def generate_jwt(
    request: JwtRequest,
    current_user: CurrentUser,
    vortex: VortexDep
):
    """Generate JWT for authenticated user"""
    try:
        user = to_vortex_user(current_user)

        # Generate JWT with optional context
        extra = {k: v for k, v in request.dict().items() if v is not None}
        jwt = vortex.generate_jwt(user=user, **extra)

        return JwtResponse(jwt=jwt)

    except VortexApiError as e:
        raise HTTPException(
            status_code=e.status_code,
            detail=e.message
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
```

**Flask Example** (`app/routes/vortex.py`):
```python
from flask import Blueprint, request, jsonify, g
from app.extensions import get_vortex_client
from app.auth import require_auth, to_vortex_user
from vortex_sdk import VortexApiError

vortex_bp = Blueprint("vortex", __name__, url_prefix="/api/vortex")

@vortex_bp.route("/jwt", methods=["POST"])
@require_auth
def generate_jwt():
    """Generate JWT for authenticated user"""
    try:
        vortex = get_vortex_client()
        user = to_vortex_user(g.user)

        # Parse optional context from request
        data = request.get_json() or {}
        extra = {
            k: v for k, v in data.items()
            if k in ["componentId", "scope", "scopeType"] and v is not None
        }

        jwt = vortex.generate_jwt(user=user, **extra)

        return jsonify({"jwt": jwt})

    except VortexApiError as e:
        return jsonify({"error": e.message, "code": "INTERNAL_ERROR"}), e.status_code
    except Exception as e:
        return jsonify({"error": "Internal server error", "code": "INTERNAL_ERROR"}), 500
```

**Django Example** (`app/views/vortex.py`):
```python
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
import json
from app.utils.vortex import get_vortex_client
from app.utils.auth import get_current_user, to_vortex_user
from vortex_sdk import VortexApiError

@require_http_methods(["POST"])
@login_required
@csrf_exempt  # If using token auth instead of session
def generate_jwt(request):
    """Generate JWT for authenticated user"""
    try:
        vortex = get_vortex_client()
        user = get_current_user(request)

        if not user:
            return JsonResponse({"error": "Unauthorized", "code": "UNAUTHORIZED"}, status=401)

        vortex_user = to_vortex_user(user)

        # Parse optional context from request body
        data = json.loads(request.body) if request.body else {}
        extra = {
            k: v for k, v in data.items()
            if k in ["componentId", "scope", "scopeType"] and v is not None
        }

        jwt = vortex.generate_jwt(user=vortex_user, **extra)

        return JsonResponse({"jwt": jwt})

    except VortexApiError as e:
        return JsonResponse({"error": e.message, "code": "INTERNAL_ERROR"}, status=e.status_code)
    except Exception:
        return JsonResponse({"error": "Internal server error", "code": "INTERNAL_ERROR"}, status=500)
```

### Step 6: Implement Invitation Query Endpoints

**FastAPI Complete Example**:
```python
from fastapi import APIRouter, HTTPException, Query, status
from typing import List, Literal
from vortex_sdk import Invitation, VortexApiError

router = APIRouter(prefix="/api/vortex", tags=["vortex"])

@router.get("/invitations")
async def get_invitations_by_target(
    type: Literal["email", "username", "phoneNumber"] = Query(...),
    value: str = Query(...),
    current_user: CurrentUser,
    vortex: VortexDep
):
    """Get invitations by target (email/phone)"""
    try:
        invitations = await vortex.get_invitations_by_target(type, value)
        return {"invitations": [inv.model_dump() for inv in invitations]}

    except VortexApiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

@router.get("/invitations/{invitation_id}")
async def get_invitation(
    invitation_id: str,
    current_user: CurrentUser,
    vortex: VortexDep
):
    """Get single invitation by ID"""
    try:
        invitation = await vortex.get_invitation(invitation_id)
        return invitation.model_dump()

    except VortexApiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

@router.get("/invitations/by-group/{group_type}/{group_id}")
async def get_invitations_by_group(
    group_type: str,
    group_id: str,
    current_user: CurrentUser,
    vortex: VortexDep
):
    """Get invitations by group"""
    try:
        invitations = await vortex.get_invitations_by_group(group_type, group_id)
        return {"invitations": [inv.model_dump() for inv in invitations]}

    except VortexApiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
```

**Flask Complete Example**:
```python
from flask import Blueprint, request, jsonify, g
from app.extensions import get_vortex_client
from app.auth import require_auth
from vortex_sdk import VortexApiError

vortex_bp = Blueprint("vortex", __name__, url_prefix="/api/vortex")

@vortex_bp.route("/invitations", methods=["GET"])
@require_auth
def get_invitations_by_target():
    """Get invitations by target"""
    try:
        vortex = get_vortex_client()
        target_type = request.args.get("type")
        target_value = request.args.get("value")

        if not target_type or not target_value:
            return jsonify({"error": "Missing type or value parameter", "code": "INVALID_REQUEST"}), 400

        invitations = vortex.get_invitations_by_target_sync(target_type, target_value)
        return jsonify({"invitations": [inv.model_dump() for inv in invitations]})

    except VortexApiError as e:
        return jsonify({"error": e.message, "code": "INTERNAL_ERROR"}), e.status_code

@vortex_bp.route("/invitations/<invitation_id>", methods=["GET"])
@require_auth
def get_invitation(invitation_id):
    """Get single invitation"""
    try:
        vortex = get_vortex_client()
        invitation = vortex.get_invitation_sync(invitation_id)
        return jsonify(invitation.model_dump())

    except VortexApiError as e:
        return jsonify({"error": e.message, "code": "INTERNAL_ERROR"}), e.status_code

@vortex_bp.route("/invitations/by-group/<group_type>/<group_id>", methods=["GET"])
@require_auth
def get_invitations_by_group(group_type, group_id):
    """Get invitations by group"""
    try:
        vortex = get_vortex_client()
        invitations = vortex.get_invitations_by_group_sync(group_type, group_id)
        return jsonify({"invitations": [inv.model_dump() for inv in invitations]})

    except VortexApiError as e:
        return jsonify({"error": e.message, "code": "INTERNAL_ERROR"}), e.status_code
```

### Step 7: Implement Accept Invitations Endpoint (CRITICAL)

**FastAPI Example with SQLAlchemy**:
```python
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import List
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import GroupMembership
from vortex_sdk import VortexApiError

class AcceptInvitationsRequest(BaseModel):
    invitationIds: List[str]
    target: dict

@router.post("/invitations/accept")
async def accept_invitations(
    request: AcceptInvitationsRequest,
    current_user: CurrentUser,
    vortex: VortexDep,
    db: Session = Depends(get_db)
):
    """Accept invitations and add user to groups"""
    try:
        # Step 1: Mark invitations as accepted in Vortex
        result = await vortex.accept_invitations(
            invitation_ids=request.invitationIds,
            target=request.target
        )

        # Step 2: CRITICAL - Add user to groups in YOUR database
        for invitation_id in request.invitationIds:
            invitation = await vortex.get_invitation(invitation_id)

            for group in invitation.groups:
                # Create or update group membership
                membership = db.query(GroupMembership).filter_by(
                    user_id=current_user["id"],
                    group_type=group.type,
                    group_id=group.group_id
                ).first()

                if not membership:
                    membership = GroupMembership(
                        user_id=current_user["id"],
                        group_type=group.type,
                        group_id=group.group_id,
                        role="member"
                    )
                    db.add(membership)

        db.commit()

        return {
            "success": True,
            "acceptedCount": len(request.invitationIds)
        }

    except VortexApiError as e:
        db.rollback()
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
```

**Flask Example with SQLAlchemy**:
```python
from flask import Blueprint, request, jsonify, g
from app.extensions import get_vortex_client, db
from app.models import GroupMembership
from app.auth import require_auth
from vortex_sdk import VortexApiError

@vortex_bp.route("/invitations/accept", methods=["POST"])
@require_auth
def accept_invitations():
    """Accept invitations and add user to groups"""
    try:
        vortex = get_vortex_client()
        data = request.get_json()
        invitation_ids = data.get("invitationIds", [])
        target = data.get("target")

        if not invitation_ids or not target:
            return jsonify({"error": "Missing invitationIds or target"}), 400

        # Step 1: Mark invitations as accepted in Vortex
        result = vortex.accept_invitations_sync(
            invitation_ids=invitation_ids,
            target=target
        )

        # Step 2: CRITICAL - Add user to groups in YOUR database
        for invitation_id in invitation_ids:
            invitation = vortex.get_invitation_sync(invitation_id)

            for group in invitation.groups:
                # Check if membership exists
                membership = GroupMembership.query.filter_by(
                    user_id=g.user["id"],
                    group_type=group.type,
                    group_id=group.group_id
                ).first()

                if not membership:
                    membership = GroupMembership(
                        user_id=g.user["id"],
                        group_type=group.type,
                        group_id=group.group_id,
                        role="member"
                    )
                    db.session.add(membership)

        db.session.commit()

        return jsonify({
            "success": True,
            "acceptedCount": len(invitation_ids)
        })

    except VortexApiError as e:
        db.session.rollback()
        return jsonify({"error": e.message, "code": "INTERNAL_ERROR"}), e.status_code
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Internal server error", "code": "INTERNAL_ERROR"}), 500
```

**Django Example with ORM**:
```python
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
import json
from app.models import GroupMembership
from app.utils.vortex import get_vortex_client
from app.utils.auth import get_current_user
from vortex_sdk import VortexApiError

@require_http_methods(["POST"])
@login_required
@csrf_exempt
def accept_invitations(request):
    """Accept invitations and add user to groups"""
    try:
        vortex = get_vortex_client()
        user = get_current_user(request)

        if not user:
            return JsonResponse({"error": "Unauthorized", "code": "UNAUTHORIZED"}, status=401)

        data = json.loads(request.body)
        invitation_ids = data.get("invitationIds", [])
        target = data.get("target")

        if not invitation_ids or not target:
            return JsonResponse(
                {"error": "Missing invitationIds or target"},
                status=400
            )

        # Step 1: Mark invitations as accepted in Vortex
        result = vortex.accept_invitations_sync(
            invitation_ids=invitation_ids,
            target=target
        )

        # Step 2: CRITICAL - Add user to groups in YOUR database
        with transaction.atomic():
            for invitation_id in invitation_ids:
                invitation = vortex.get_invitation_sync(invitation_id)

                for group in invitation.groups:
                    # Create or update group membership
                    GroupMembership.objects.update_or_create(
                        user_id=user["id"],
                        group_type=group.type,
                        group_id=group.group_id,
                        defaults={"role": "member"}
                    )

        return JsonResponse({
            "success": True,
            "acceptedCount": len(invitation_ids)
        })

    except VortexApiError as e:
        return JsonResponse({"error": e.message, "code": "INTERNAL_ERROR"}, status=e.status_code)
    except Exception:
        return JsonResponse({"error": "Internal server error", "code": "INTERNAL_ERROR"}, status=500)
```

### Step 8: Implement Delete/Revoke Endpoints

**FastAPI Example**:
```python
@router.delete("/invitations/{invitation_id}")
async def revoke_invitation(
    invitation_id: str,
    current_user: CurrentUser,
    vortex: VortexDep
):
    """Revoke an invitation"""
    try:
        # Optional: Add authorization check
        # if not current_user.get("is_admin"):
        #     raise HTTPException(status_code=403, detail="Forbidden")

        result = await vortex.revoke_invitation(invitation_id)
        return {"success": True}

    except VortexApiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

@router.delete("/invitations/by-group/{group_type}/{group_id}")
async def delete_invitations_by_group(
    group_type: str,
    group_id: str,
    current_user: CurrentUser,
    vortex: VortexDep
):
    """Delete all invitations for a group (admin only)"""
    try:
        if not current_user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Forbidden")

        result = await vortex.delete_invitations_by_group(group_type, group_id)
        return {"success": True}

    except VortexApiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)

@router.post("/invitations/{invitation_id}/reinvite")
async def reinvite(
    invitation_id: str,
    current_user: CurrentUser,
    vortex: VortexDep
):
    """Resend invitation"""
    try:
        invitation = await vortex.reinvite(invitation_id)
        return {"success": True}

    except VortexApiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
```

### Step 9: Database Models

**SQLAlchemy Model**:
```python
from sqlalchemy import Column, Integer, String, DateTime, UniqueConstraint, Index
from sqlalchemy.sql import func
from app.database import Base

class GroupMembership(Base):
    __tablename__ = "group_memberships"

    id = Column(Integer, primary_key=True)
    user_id = Column(String(255), nullable=False)
    group_type = Column(String(100), nullable=False)
    group_id = Column(String(255), nullable=False)
    role = Column(String(50), default="member")
    joined_at = Column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("user_id", "group_type", "group_id", name="unique_membership"),
        Index("idx_group", "group_type", "group_id"),
        Index("idx_user", "user_id"),
    )
```

**Django Model**:
```python
from django.db import models

class GroupMembership(models.Model):
    user_id = models.CharField(max_length=255)
    group_type = models.CharField(max_length=100)
    group_id = models.CharField(max_length=255)
    role = models.CharField(max_length=50, default="member")
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "group_memberships"
        unique_together = [["user_id", "group_type", "group_id"]]
        indexes = [
            models.Index(fields=["group_type", "group_id"]),
            models.Index(fields=["user_id"]),
        ]
```

**Alembic Migration** (for SQLAlchemy):
```python
"""create group_memberships table

Revision ID: abc123
"""
from alembic import op
import sqlalchemy as sa

def upgrade():
    op.create_table(
        "group_memberships",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.String(255), nullable=False),
        sa.Column("group_type", sa.String(100), nullable=False),
        sa.Column("group_id", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), server_default="member"),
        sa.Column("joined_at", sa.DateTime(), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "group_type", "group_id", name="unique_membership"),
    )
    op.create_index("idx_group", "group_memberships", ["group_type", "group_id"])
    op.create_index("idx_user", "group_memberships", ["user_id"])

def downgrade():
    op.drop_table("group_memberships")
```

---

## Build and Validation

### Type Checking
```bash
mypy app/
```

### Linting
```bash
ruff check app/
```

### Code Formatting
```bash
black app/
isort app/
```

### Run Tests
```bash
pytest tests/
```

### Start Development Server

**FastAPI**:
```bash
uvicorn app.main:app --reload
```

**Flask**:
```bash
flask run --debug
```

**Django**:
```bash
python manage.py runserver
```

### Test Endpoints

**1. Generate JWT**:
```bash
curl -X POST http://localhost:8000/api/vortex/jwt \
  -H "Authorization: Bearer your-auth-token" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**2. Get Invitations by Target**:
```bash
curl -X GET "http://localhost:8000/api/vortex/invitations?type=email&value=user@example.com" \
  -H "Authorization: Bearer your-auth-token"
```

**3. Accept Invitations**:
```bash
curl -X POST http://localhost:8000/api/vortex/invitations/accept \
  -H "Authorization: Bearer your-auth-token" \
  -H "Content-Type: application/json" \
  -d '{
    "invitationIds": ["inv-123"],
    "target": {"type": "email", "value": "user@example.com"}
  }'
```

---

## Implementation Report

After implementing, provide this structured report:

```markdown
## Vortex Python SDK Integration Report

### Files Created/Modified
- [ ] `requirements.txt` or `pyproject.toml` - Added vortex-python-sdk dependency
- [ ] `app/lib/vortex_client.py` (or dependencies.py) - Vortex client setup
- [ ] `app/lib/auth.py` - Authentication utilities
- [ ] `app/routers/vortex.py` (or views/routes) - Vortex endpoints
- [ ] `app/models.py` - GroupMembership model
- [ ] `alembic/versions/xxx_create_group_memberships.py` - Database migration

### Framework Used
- [ ] FastAPI (async)
- [ ] Flask (sync)
- [ ] Django (sync)
- [ ] Starlette (async)
- [ ] Other: ___

### Endpoints Implemented
- [x] `POST /api/vortex/jwt` - JWT generation
- [x] `GET /api/vortex/invitations` - Get invitations by target
- [x] `POST /api/vortex/invitations/accept` - Accept invitations (with database logic)
- [x] `GET /api/vortex/invitations/{id}` - Get single invitation
- [x] `DELETE /api/vortex/invitations/{id}` - Revoke invitation
- [x] `POST /api/vortex/invitations/{id}/reinvite` - Resend invitation
- [x] `GET /api/vortex/invitations/by-group/{type}/{id}` - Get invitations by group
- [x] `DELETE /api/vortex/invitations/by-group/{type}/{id}` - Delete invitations by group

### Database Integration
- [x] Created `GroupMembership` model
- [x] Created database migration
- [x] Implemented database insert logic in accept endpoint
- [x] Added database indexes
- [x] Tested database inserts

### Configuration
- [x] Set `VORTEX_API_KEY` environment variable
- [x] Created Vortex client instance
- [x] Implemented authentication extraction
- [x] Set up error handling

### Testing Results
- [ ] JWT generation: ✓ Working
- [ ] Get invitations by target: ✓ Working
- [ ] Accept invitations: ✓ Working (database inserts confirmed)
- [ ] Get single invitation: ✓ Working
- [ ] Revoke invitation: ✓ Working
- [ ] Reinvite: ✓ Working
- [ ] Get invitations by group: ✓ Working
- [ ] Delete invitations by group: ✓ Working

### Notes
- Framework: [FastAPI / Flask / Django]
- Async: [Yes / No]
- ORM: [SQLAlchemy / Django ORM / other]
- Authentication: [JWT / Session / other]
```

---

## Common Issues and Solutions

### Issue 1: "ModuleNotFoundError: No module named 'vortex_sdk'"
**Solution**: Install the package:
```bash
pip install vortex-python-sdk
# or
poetry add vortex-python-sdk
```

### Issue 2: "VORTEX_API_KEY environment variable not set"
**Solution**: Load environment variables using python-dotenv:
```python
from dotenv import load_dotenv
load_dotenv()
```

### Issue 3: Accept invitations succeeds but user not added to groups
**Solution**: Database logic not implemented. Check:
- Database connection is working
- Model is properly defined
- Migration has been run
- Database inserts are executing
- Check logs for errors

### Issue 4: "RuntimeError: await wasn't used with Future"
**Solution**: Using async method in sync context. Use sync version:
```python
# Wrong
invitations = vortex.get_invitations_by_target("email", "user@example.com")

# Correct (async)
invitations = await vortex.get_invitations_by_target("email", "user@example.com")

# Correct (sync)
invitations = vortex.get_invitations_by_target_sync("email", "user@example.com")
```

### Issue 5: Type errors with Pydantic models
**Solution**: Import types explicitly:
```python
from vortex_sdk import User, Invitation, InvitationTarget
```

### Issue 6: CORS errors from frontend
**Solution**: Add CORS middleware:

**FastAPI**:
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Flask**:
```python
from flask_cors import CORS

CORS(app, origins=["http://localhost:3000"], supports_credentials=True)
```

---

## Best Practices

### 1. Use Context Managers
```python
# Properly close HTTP connections
async with Vortex(api_key=api_key) as vortex:
    invitations = await vortex.get_invitations_by_target("email", "user@example.com")
```

### 2. Type Hints
```python
from vortex_sdk import Vortex, User, Invitation
from typing import List

async def get_user_invitations(vortex: Vortex, email: str) -> List[Invitation]:
    return await vortex.get_invitations_by_target("email", email)
```

### 3. Error Handling
```python
from vortex_sdk import VortexApiError

try:
    invitation = await vortex.get_invitation(invitation_id)
except VortexApiError as e:
    logger.error(f"Vortex API error: {e.message} (status: {e.status_code})")
    raise
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    raise
```

### 4. Database Transactions
```python
# SQLAlchemy
with db.begin():
    # Multiple database operations

# Django
with transaction.atomic():
    # Multiple database operations
```

### 5. Environment Configuration
```python
# Use Pydantic Settings for configuration
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    vortex_api_key: str
    database_url: str

    class Config:
        env_file = ".env"

settings = Settings()
```

### 6. Dependency Injection
```python
# FastAPI dependency injection
from typing import Annotated

VortexDep = Annotated[Vortex, Depends(get_vortex_client)]

async def endpoint(vortex: VortexDep):
    # Use vortex client
    pass
```

### 7. Async Best Practices
```python
# Don't mix async and sync
# Wrong
def sync_function():
    result = await vortex.get_invitation(id)  # Error!

# Correct
async def async_function():
    result = await vortex.get_invitation(id)  # OK

# Or use sync version
def sync_function():
    result = vortex.get_invitation_sync(id)  # OK
```

### 8. Testing
```python
import pytest
from vortex_sdk import Vortex

@pytest.fixture
def vortex_client():
    return Vortex(api_key="test-api-key")

@pytest.mark.asyncio
async def test_generate_jwt(vortex_client):
    user = {"id": "test-123", "email": "test@example.com"}
    jwt = vortex_client.generate_jwt(user=user)
    assert jwt
```

---

## Additional Resources

- **Python SDK README**: `packages/vortex-python-sdk/README.md`
- **PyPI Package**: https://pypi.org/project/vortex-python-sdk/
- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **Flask Documentation**: https://flask.palletsprojects.com/
- **Django Documentation**: https://docs.djangoproject.com/
- **Pydantic Documentation**: https://docs.pydantic.dev/
