# Vortex Python SDK Implementation Guide

**Package:** `vortex-python-sdk`
**Type:** Base SDK (Core library for Python applications)
**Requires:** Python 3.8+

## Prerequisites
From integration contract you need: API endpoint prefix, scope entity, authentication pattern
From discovery data you need: Python framework (FastAPI, Flask, Django), database ORM, async/sync, auth pattern

## Key Facts
- Framework-agnostic Python SDK
- Dual async/sync API - every method has both versions
- Type-safe with Pydantic models
- Client-based: instantiate `Vortex` class and call methods
- Accept invitations requires custom database logic (must implement)
- Context manager support for proper resource cleanup

---

## Step 1: Install

```bash
pip install vortex-python-sdk
# or
poetry add vortex-python-sdk
```

---

## Step 2: Set Environment Variable

Add to `.env`:

```bash
VORTEX_API_KEY=VRTX.your-api-key-here.secret
```

Load in Python:
```python
from dotenv import load_dotenv
import os

load_dotenv()
api_key = os.getenv("VORTEX_API_KEY")
```

**Never commit API key to version control.**

---

## Step 3: Create Vortex Client

### Singleton Pattern (`app/lib/vortex_client.py`):
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

### FastAPI Dependency (`app/dependencies.py`):
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

### Django Settings:
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

### Flask Extension (`app/extensions.py`):
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

---

## Step 4: Extract Authenticated User

### FastAPI:
```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Annotated
from vortex_sdk import User

security = HTTPBearer()

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]
) -> dict:
    """Extract user from JWT token"""
    token = credentials.credentials

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

### Flask:
```python
from flask import g, request
from functools import wraps
from typing import Optional
from vortex_sdk import User

def get_current_user() -> Optional[dict]:
    """Get current user from session or JWT"""
    # Session-based
    from flask import session
    if "user_id" in session:
        return {
            "id": session["user_id"],
            "email": session["user_email"],
            "is_admin": session.get("is_admin", False)
        }

    # JWT-based
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = decode_jwt(token)
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
    return User(
        id=str(user["id"]),
        email=user["email"],
        admin_scopes=["autojoin"] if user.get("is_admin") else None
    )
```

### Django:
```python
from django.contrib.auth.decorators import login_required
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
    return User(
        id=user["id"],
        email=user["email"],
        admin_scopes=["autojoin"] if user.get("is_admin") else None
    )
```

**Adapt to their patterns:**
- Match their auth mechanism (JWT, sessions, framework auth)
- Match their user structure
- Match their admin detection logic

---

## Step 5: Implement JWT Generation Endpoint

### FastAPI (`app/routers/vortex.py`):
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
        extra = {k: v for k, v in request.dict().items() if v is not None}
        jwt = vortex.generate_jwt(user=user, **extra)

        return JwtResponse(jwt=jwt)

    except VortexApiError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
```

### Flask (`app/routes/vortex.py`):
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

        data = request.get_json() or {}
        extra = {
            k: v for k, v in data.items()
            if k in ["componentId", "scope", "scopeType"] and v is not None
        }

        jwt = vortex.generate_jwt(user=user, **extra)

        return jsonify({"jwt": jwt})

    except VortexApiError as e:
        return jsonify({"error": e.message, "code": "INTERNAL_ERROR"}), e.status_code
    except Exception:
        return jsonify({"error": "Internal server error", "code": "INTERNAL_ERROR"}), 500
```

### Django (`app/views/vortex.py`):
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
@csrf_exempt
def generate_jwt(request):
    """Generate JWT for authenticated user"""
    try:
        vortex = get_vortex_client()
        user = get_current_user(request)

        if not user:
            return JsonResponse({"error": "Unauthorized", "code": "UNAUTHORIZED"}, status=401)

        vortex_user = to_vortex_user(user)

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

---

## Step 6: Implement Accept Invitations Endpoint (CRITICAL)

### FastAPI with SQLAlchemy:
```python
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel
from typing import List
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import GroupMembership
from vortex_sdk import VortexApiError

class AcceptInvitationsRequest(BaseModel):
    invitationIds: List[str]
    user: dict

@router.post("/invitations/accept")
async def accept_invitations(
    request: AcceptInvitationsRequest,
    current_user: CurrentUser,
    vortex: VortexDep,
    db: Session = Depends(get_db)
):
    """Accept invitations and add user to groups"""
    try:
        # 1. Mark as accepted in Vortex
        result = await vortex.accept_invitations(
            invitation_ids=request.invitationIds,
            user=request.user
        )

        # 2. CRITICAL - Add to database
        for invitation_id in request.invitationIds:
            invitation = await vortex.get_invitation(invitation_id)

            for group in invitation.groups:
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
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )
```

### Flask with SQLAlchemy:
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
        user = data.get("user")

        if not invitation_ids or not user:
            return jsonify({"error": "Missing invitationIds or user"}), 400

        # 1. Mark as accepted in Vortex
        result = vortex.accept_invitations_sync(
            invitation_ids=invitation_ids,
            user=user
        )

        # 2. CRITICAL - Add to database
        for invitation_id in invitation_ids:
            invitation = vortex.get_invitation_sync(invitation_id)

            for group in invitation.groups:
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

### Django with ORM:
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
        user = data.get("user")

        if not invitation_ids or not user:
            return JsonResponse({"error": "Missing invitationIds or user"}, status=400)

        # 1. Mark as accepted in Vortex
        result = vortex.accept_invitations_sync(
            invitation_ids=invitation_ids,
            user=user
        )

        # 2. CRITICAL - Add to database
        with transaction.atomic():
            for invitation_id in invitation_ids:
                invitation = vortex.get_invitation_sync(invitation_id)

                for group in invitation.groups:
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

**Critical - Adapt database logic:**
- Use their actual table/model names (from discovery)
- Use their actual field names
- Use their ORM pattern (SQLAlchemy, Django ORM)
- Handle duplicate memberships if needed
- Use async methods for FastAPI, sync for Flask/Django

---

## Step 7: Database Models

### SQLAlchemy:
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

### Django:
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

---

## Step 8: Build and Test

```bash
# FastAPI
uvicorn app.main:app --reload

# Flask
flask run --debug

# Django
python manage.py runserver

# Test JWT endpoint
curl -X POST http://localhost:8000/api/vortex/jwt \
  -H "Authorization: Bearer your-auth-token"
```

Expected response:
```json
{
  "jwt": "eyJhbGciOiJIUzI1NiIs..."
}
```

---

## Common Errors

**"ModuleNotFoundError: No module named 'vortex_sdk'"** → Run `pip install vortex-python-sdk`

**"VORTEX_API_KEY not set"** → Load environment with `python-dotenv`

**User not added to database** → Must implement database logic in accept handler (see Step 6)

**"RuntimeError: await wasn't used with Future"** → Use sync version:
```python
# Async (FastAPI)
invitations = await vortex.get_invitations_by_target("email", "user@example.com")

# Sync (Flask/Django)
invitations = vortex.get_invitations_by_target_sync("email", "user@example.com")
```

**CORS errors** → Add CORS middleware:
```python
# FastAPI
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Flask
from flask_cors import CORS
CORS(app, origins=["http://localhost:3000"], supports_credentials=True)
```

---

## After Implementation Report

List files created/modified:
- Dependency: requirements.txt or pyproject.toml
- Client: app/lib/vortex_client.py (or dependencies.py)
- Auth: app/lib/auth.py
- Endpoints: app/routers/vortex.py (or routes/views)
- Models: app/models.py
- Migration: Database migration for group_memberships

Confirm:
- Vortex SDK installed
- VortexClient instance created
- JWT endpoint returns valid JWT
- Accept invitations includes database logic
- Routes registered at correct prefix
- Database migration run

## Endpoints Registered

All endpoints at `/api/vortex`:
- `POST /jwt` - Generate JWT for authenticated user
- `GET /invitations` - Get invitations by target
- `GET /invitations/:id` - Get invitation by ID
- `POST /invitations/accept` - Accept invitations (custom DB logic)
- `DELETE /invitations/:id` - Revoke invitation
- `POST /invitations/:id/reinvite` - Resend invitation
