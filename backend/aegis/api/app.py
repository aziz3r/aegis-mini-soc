"""FastAPI application: lifespan, CORS, WebSocket, static front-end.

The model is loaded once at startup. If it is missing the API still starts, in a
degraded mode that answers every detection route with a 503 carrying the exact
command to run - a server that refuses to boot tells the operator nothing.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from aegis import __version__
from aegis.api.pipeline import Pipeline
from aegis.api.routes import router
from aegis.config import REPO_ROOT, settings
from aegis.core.assets import Asset, AssetRegistry
from aegis.ml.model import DetectionModel
from aegis.store.db import Setting, init_db, session_scope

FRONTEND_DIST = REPO_ROOT / "frontend" / "dist"


def _load_assets() -> AssetRegistry:
    """Asset inventory from the database, falling back to the shipped defaults."""
    with contextlib.suppress(Exception):
        with session_scope() as sess:
            row = sess.get(Setting, "assets")
            if row and row.value.get("entries"):
                return AssetRegistry([
                    Asset(cidr=e["cidr"], name=e["name"],
                          criticality=int(e.get("criticality", 3)), tags=list(e.get("tags", [])))
                    for e in row.value["entries"]
                ])
    return AssetRegistry()


def _load_detection_settings() -> None:
    with contextlib.suppress(Exception):
        with session_scope() as sess:
            row = sess.get(Setting, "detection")
            if row and row.value:
                for field, value in row.value.items():
                    if hasattr(settings, field):
                        setattr(settings, field, value)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db()
    _load_detection_settings()
    app.state.model_error = None
    app.state.pipeline = None
    try:
        model = DetectionModel.load()
        app.state.pipeline = Pipeline(model, assets=_load_assets())
    except FileNotFoundError:
        app.state.model_error = (
            "aucun modèle entraîné dans data/models — lancez « aegis train »"
        )
    except Exception as exc:
        app.state.model_error = f"modèle illisible : {exc}"

    autostart = os.environ.get("AEGIS_AUTOSTART", "").strip().lower()
    if app.state.pipeline is not None and autostart in {"lab", "1", "true", "yes"}:
        speed = float(os.environ.get("AEGIS_AUTOSTART_SPEED", "1") or 1)
        await app.state.pipeline.start_lab(duration=86_400, speed=speed)
    try:
        yield
    finally:
        if app.state.pipeline is not None:
            await app.state.pipeline.stop()


app = FastAPI(
    title="AEGIS Mini-SOC",
    version=__version__,
    description=(
        "Détection d'intrusion réseau par apprentissage automatique.\n\n"
        "Chaîne complète : assemblage de flux → 52 features → anomalie non supervisée "
        "calibrée → classification de famille → seuil adaptatif par hôte → corrélation "
        "en incidents → triage."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)


@app.get("/api/health", tags=["meta"])
async def health() -> dict:
    pipeline = app.state.pipeline
    return {
        "status": "ok" if pipeline is not None else "degraded",
        "version": __version__,
        "model_loaded": pipeline is not None,
        "model_error": app.state.model_error,
        "pipeline_running": bool(pipeline and pipeline.is_running),
        "database": settings.database_url.split("///")[-1],
    }


@app.get("/api/stream/history", tags=["dashboard"])
async def stream_history() -> dict:
    pipeline = app.state.pipeline
    if pipeline is None:
        return {"items": []}
    return {"items": pipeline.bus.history()}


@app.websocket("/api/stream")
async def stream(websocket: WebSocket) -> None:
    """Live tick stream.

    Authentication is by `?token=` because the browser WebSocket API cannot set
    an Authorization header. The token is the same JWT the REST API uses.
    """
    from aegis.api.auth import ALGORITHM
    from jose import JWTError, jwt

    token = websocket.query_params.get("token", "")
    try:
        jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    except JWTError:
        await websocket.close(code=4401, reason="jeton invalide")
        return

    pipeline = app.state.pipeline
    if pipeline is None:
        await websocket.close(code=4503, reason="aucun modèle chargé")
        return

    await websocket.accept()
    subscription = pipeline.bus.subscribe()
    try:
        await websocket.send_json({"type": "hello", "version": __version__,
                                   "history": pipeline.bus.history(),
                                   "status": pipeline.status()})
        async for event in subscription.__aiter__():
            await websocket.send_json(event)
    except (WebSocketDisconnect, asyncio.CancelledError, RuntimeError):
        pass
    finally:
        subscription.close()


# ------------------------------------------------------- built front-end (SPA)

if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.middleware("http")
    async def _asset_cache_headers(request, call_next):
        """Content-hashed assets are immutable; the SPA shell never is."""
        response = await call_next(request)
        if request.url.path.startswith("/assets/") and response.status_code == 200:
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        return response

    #: The build gives every asset a content hash in its name, so assets can be
    #: cached forever. `index.html` must not be: it is the only file whose name
    #: never changes, and a cached copy pins the browser to the previous build's
    #: asset names - the app keeps running the old code after a deploy, silently.
    _NO_STORE = {"Cache-Control": "no-cache, must-revalidate"}
    _IMMUTABLE = {"Cache-Control": "public, max-age=31536000, immutable"}

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        if full_path.startswith("api/"):
            return JSONResponse({"detail": "not found"}, status_code=404)
        candidate = (FRONTEND_DIST / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(FRONTEND_DIST.resolve()):
            headers = _IMMUTABLE if "/assets/" in f"/{full_path}" else _NO_STORE
            return FileResponse(candidate, headers=headers)
        return FileResponse(FRONTEND_DIST / "index.html", headers=_NO_STORE)
else:
    @app.get("/", include_in_schema=False)
    async def no_frontend() -> dict:
        return {
            "message": "interface web non compilée",
            "hint": "cd frontend && npm install && npm run build  (ou npm run dev sur le port 5173)",
            "api_docs": "/docs",
        }
