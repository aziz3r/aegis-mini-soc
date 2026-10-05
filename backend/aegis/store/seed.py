"""Default accounts and settings, created by `aegis init`."""
from __future__ import annotations

import secrets

from aegis.core.assets import DEFAULT_ASSETS
from aegis.store.db import Setting, User, session_scope

DEFAULT_USERS = [("admin", "admin"), ("analyste", "analyst"), ("lecteur", "viewer")]


def seed_defaults(admin_password: str | None = None) -> list[str]:
    from aegis.api.auth import hash_password

    created: list[str] = []
    with session_scope() as sess:
        for username, role in DEFAULT_USERS:
            if sess.get(User, username):
                continue
            password = admin_password if (username == "admin" and admin_password) else secrets.token_urlsafe(9)
            sess.add(User(username=username, password_hash=hash_password(password), role=role))
            created.append(f"compte « {username} » ({role}) — mot de passe : {password}")
        if not sess.get(Setting, "assets"):
            sess.add(Setting(key="assets", value={
                "entries": [{"cidr": a.cidr, "name": a.name, "criticality": a.criticality,
                             "tags": a.tags} for a in DEFAULT_ASSETS]}))
            created.append(f"inventaire d'actifs par défaut ({len(DEFAULT_ASSETS)} entrées)")
    if not created:
        created.append("rien à créer : la base contenait déjà les comptes et les réglages")
    return created
