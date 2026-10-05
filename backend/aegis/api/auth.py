"""Authentication and roles.

Three roles, enforced server-side on every mutating endpoint:

  viewer   read everything, change nothing
  analyst  triage incidents (acknowledge, assign, close, annotate)
  admin    everything, plus settings, thresholds and the asset inventory

Password hashing uses `hashlib.scrypt` from the standard library rather than
passlib + bcrypt: one less dependency, no version drift between passlib and
bcrypt releases, and scrypt is memory-hard. The stored format carries its own
parameters, so they can be raised later without invalidating existing hashes.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from aegis.config import settings
from aegis.store.db import User, session_scope

ALGORITHM = "HS256"
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


class Principal(BaseModel):
    username: str
    role: str

    def can(self, required: str) -> bool:
        return ROLE_RANK.get(self.role, -1) >= ROLE_RANK.get(required, 99)


# ------------------------------------------------------------------- passwords

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex),
            n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(digest_hex)),
        )
    except (ValueError, TypeError):
        return False
    # constant time, so a wrong password cannot be found byte by byte via timing
    return hmac.compare_digest(digest.hex(), digest_hex)


# ---------------------------------------------------------------------- tokens

def create_token(username: str, role: str) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_ttl_minutes)
    payload = {"sub": username, "role": role, "exp": expires}
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def authenticate(username: str, password: str) -> Principal | None:
    with session_scope() as sess:
        user = sess.get(User, username)
        if user is None or not verify_password(password, user.password_hash):
            return None
        return Principal(username=user.username, role=user.role)


# ------------------------------------------------------------------ dependency

async def current_principal(token: Annotated[str | None, Depends(oauth2_scheme)]) -> Principal:
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentification requise",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "jeton invalide ou expiré",
                            headers={"WWW-Authenticate": "Bearer"}) from None
    username, role = payload.get("sub"), payload.get("role", "viewer")
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "jeton incomplet")
    return Principal(username=str(username), role=str(role))


def require(role: str):
    """Dependency factory: `Depends(require("analyst"))`."""

    async def _dep(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
        if not principal.can(role):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"rôle « {role} » requis (le vôtre : « {principal.role} »)",
            )
        return principal

    return _dep


CurrentUser = Annotated[Principal, Depends(current_principal)]
AnalystUser = Annotated[Principal, Depends(require("analyst"))]
AdminUser = Annotated[Principal, Depends(require("admin"))]
