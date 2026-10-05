"""REST endpoints.

Every mutating route names the role it requires and writes an audit entry. The
read routes are deliberately shaped around the screens that consume them - one
request per view, not one request per widget - so the UI stays responsive without
a client-side cache.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy import case, desc, func, select

from aegis.api.auth import AdminUser, AnalystUser, CurrentUser, authenticate, create_token
from aegis.api.schemas import (
    AssetsIn, BulkAction, DetectionSettingsIn, IncidentPatch, StartLab, StartLive, StartPcap, TokenOut,
)
from aegis.config import settings
from aegis.core.assets import Asset, AssetRegistry
from aegis.core.features import FEATURE_NAMES
from aegis.core.mitre import FAMILIES, info as mitre_info
from aegis.store.db import Alert, AuditEntry, Bucket, Host, Incident, Setting, session_scope
from aegis.store.writer import Writer, incident_payload

router = APIRouter(prefix="/api")

OPEN_STATUSES = ("NEW", "ACK", "INVESTIGATING")
SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


def _pipeline(request: Request):
    pipeline = getattr(request.app.state, "pipeline", None)
    if pipeline is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "aucun modèle chargé — lancez `aegis train` puis redémarrez l'API",
        )
    return pipeline


# ----------------------------------------------------------------------- auth

@router.post("/auth/token", response_model=TokenOut, tags=["auth"])
async def login(request: Request) -> TokenOut:
    form = await request.form()
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    principal = authenticate(username, password)
    if principal is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "identifiants invalides")
    Writer.audit(principal.username, "login")
    return TokenOut(
        access_token=create_token(principal.username, principal.role),
        username=principal.username, role=principal.role,
        expires_in_minutes=settings.jwt_ttl_minutes,
    )


@router.get("/auth/me", tags=["auth"])
async def whoami(user: CurrentUser) -> dict:
    return {"username": user.username, "role": user.role}


# ------------------------------------------------------------------- overview

@router.get("/overview", tags=["dashboard"])
async def overview(user: CurrentUser, hours: int = Query(default=24, ge=1, le=720)) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    with session_scope() as sess:
        by_severity = dict(sess.execute(
            select(Incident.severity, func.count()).where(Incident.status.in_(OPEN_STATUSES))
            .group_by(Incident.severity)
        ).all())
        by_status = dict(sess.execute(
            select(Incident.status, func.count()).group_by(Incident.status)
        ).all())
        by_family = dict(sess.execute(
            select(Incident.family, func.count()).where(Incident.last_seen >= since)
            .group_by(Incident.family).order_by(desc(func.count())).limit(12)
        ).all())
        top_sources = [
            {"ip": ip, "incidents": n, "alerts": int(occ or 0), "max_severity": sev}
            for ip, n, occ, sev in sess.execute(
                select(Incident.src, func.count(), func.sum(Incident.occurrences),
                       func.max(case(*[(Incident.severity == s, r) for s, r in SEVERITY_RANK.items()], else_=0)))
                .where(Incident.last_seen >= since)
                .group_by(Incident.src).order_by(desc(func.sum(Incident.occurrences))).limit(8)
            ).all()
        ]
        top_targets = [
            {"ip": ip, "incidents": n, "asset": name, "criticality": crit}
            for ip, n, name, crit in sess.execute(
                select(Incident.dst, func.count(), func.max(Incident.asset_name),
                       func.max(Incident.criticality))
                .where(Incident.last_seen >= since)
                .group_by(Incident.dst).order_by(desc(func.count())).limit(8)
            ).all()
        ]
        totals = sess.execute(
            select(func.count(), func.sum(Incident.occurrences))
            .where(Incident.last_seen >= since)
        ).one()
        closed = sess.execute(
            select(func.count(), func.avg(
                func.julianday(Incident.closed_at) - func.julianday(Incident.first_seen)))
            .where(Incident.closed_at.is_not(None), Incident.closed_at >= since)
        ).one() if settings.database_url.startswith("sqlite") else (0, None)
        fp = sess.scalar(select(func.count()).where(Incident.verdict == "FP", Incident.closed_at >= since)) or 0
        tp = sess.scalar(select(func.count()).where(Incident.verdict == "TP", Incident.closed_at >= since)) or 0
        buckets = [
            {"ts": b.ts.isoformat(), "flows": b.flows, "alerts": b.alerts, "bytes": b.bytes,
             "score_mean": round(b.score_mean, 4), "score_max": round(b.score_max, 4),
             "threshold": round(b.threshold_mean, 4)}
            for b in sess.scalars(
                select(Bucket).where(Bucket.ts >= since).order_by(desc(Bucket.ts)).limit(600)
            ).all()
        ][::-1]
        hourly = _hourly_heatmap(sess, since)

    mttr_days = closed[1] if closed and closed[1] else None
    return {
        "window_hours": hours,
        "open_by_severity": {k: int(v) for k, v in by_severity.items()},
        "by_status": {k: int(v) for k, v in by_status.items()},
        "by_family": {k: int(v) for k, v in by_family.items()},
        "top_sources": top_sources,
        "top_targets": top_targets,
        "incidents_total": int(totals[0] or 0),
        "alerts_total": int(totals[1] or 0),
        "closed_total": int(closed[0] or 0) if closed else 0,
        "mean_time_to_close_minutes": round(mttr_days * 24 * 60, 1) if mttr_days else None,
        "feedback": {"true_positive": tp, "false_positive": fp,
                     "precision_observed": round(tp / (tp + fp), 4) if (tp + fp) else None},
        "buckets": buckets,
        "hourly": hourly,
    }


def _hourly_heatmap(sess, since: datetime) -> list[dict]:
    rows = sess.execute(
        select(func.strftime("%Y-%m-%dT%H:00", Incident.last_seen).label("hour"),
               Incident.severity, func.count())
        .where(Incident.last_seen >= since).group_by("hour", Incident.severity)
    ).all() if settings.database_url.startswith("sqlite") else []
    out: dict[str, dict] = {}
    for hour, severity, count in rows:
        slot = out.setdefault(str(hour), {"hour": str(hour), "total": 0})
        slot[str(severity).lower()] = int(count)
        slot["total"] += int(count)
    return sorted(out.values(), key=lambda r: r["hour"])


# ------------------------------------------------------------------ incidents

@router.get("/incidents", tags=["incidents"])
async def list_incidents(
    user: CurrentUser,
    status_filter: str | None = Query(default=None, alias="status"),
    severity: str | None = None,
    family: str | None = None,
    src: str | None = None,
    dst: str | None = None,
    q: str | None = None,
    open_only: bool = False,
    hours: int | None = Query(default=None, ge=1, le=8760),
    sort: str = Query(default="priority", pattern="^(priority|last_seen|occurrences|score_max)$"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    stmt = select(Incident)
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter.upper())
    if open_only:
        stmt = stmt.where(Incident.status.in_(OPEN_STATUSES))
    if severity:
        stmt = stmt.where(Incident.severity == severity.upper())
    if family:
        stmt = stmt.where(Incident.family == family.upper())
    if src:
        stmt = stmt.where(Incident.src.like(f"%{src}%"))
    if dst:
        stmt = stmt.where(Incident.dst.like(f"%{dst}%"))
    if hours:
        stmt = stmt.where(Incident.last_seen >= datetime.now(timezone.utc) - timedelta(hours=hours))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            Incident.src.like(like) | Incident.dst.like(like)
            | Incident.family.like(like) | Incident.asset_name.like(like)
            | Incident.mitre_technique.like(like)
        )
    order = {"priority": desc(Incident.priority), "last_seen": desc(Incident.last_seen),
             "occurrences": desc(Incident.occurrences), "score_max": desc(Incident.score_max)}[sort]

    with session_scope() as sess:
        total = sess.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = sess.scalars(
            stmt.order_by(order, desc(Incident.last_seen)).limit(limit).offset(offset)
        ).all()
        items = [incident_payload(r) for r in rows]
    return {"total": int(total), "limit": limit, "offset": offset, "items": items}


@router.get("/incidents/{incident_id}", tags=["incidents"])
async def get_incident(incident_id: int, user: CurrentUser,
                       alerts: int = Query(default=100, ge=1, le=1000)) -> dict:
    with session_scope() as sess:
        row = sess.get(Incident, incident_id)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident inconnu")
        payload = incident_payload(row)
        alert_rows = sess.scalars(
            select(Alert).where(Alert.incident_id == incident_id)
            .order_by(desc(Alert.score)).limit(alerts)
        ).all()
        timeline = sess.execute(
            select(func.strftime("%Y-%m-%dT%H:%M:%S", Alert.ts), func.count(), func.max(Alert.score))
            .where(Alert.incident_id == incident_id).group_by(func.strftime("%Y-%m-%dT%H:%M:%S", Alert.ts))
            .order_by(func.strftime("%Y-%m-%dT%H:%M:%S", Alert.ts)).limit(500)
        ).all() if settings.database_url.startswith("sqlite") else []
        ports = [
            {"port": p, "count": int(n)} for p, n in sess.execute(
                select(Alert.dport, func.count()).where(Alert.incident_id == incident_id)
                .group_by(Alert.dport).order_by(desc(func.count())).limit(20)
            ).all()
        ]
        peers = [
            {"ip": ip, "count": int(n)} for ip, n in sess.execute(
                select(Alert.src, func.count()).where(Alert.incident_id == incident_id)
                .group_by(Alert.src).order_by(desc(func.count())).limit(20)
            ).all()
        ]
        truth = dict(sess.execute(
            select(Alert.truth, func.count()).where(Alert.incident_id == incident_id)
            .group_by(Alert.truth)
        ).all())

    guidance = mitre_info(payload["family"])
    payload.update({
        "alerts": [
            {
                "id": a.id, "ts": a.ts.isoformat(), "src": a.src, "sport": a.sport,
                "dst": a.dst, "dport": a.dport, "proto": a.proto,
                "score": round(a.score, 4), "threshold": round(a.threshold, 4),
                "family": a.family, "confidence": round(a.confidence, 4),
                "severity": a.severity, "packets": a.packets, "bytes": a.bytes,
                "duration": round(a.duration, 3), "truth": a.truth,
                "contributions": a.contributions or [],
                "flow_start": a.flow_start, "flow_end": a.flow_end,
            }
            for a in alert_rows
        ],
        "timeline": [{"ts": t, "count": int(c), "score_max": round(float(s or 0), 4)}
                     for t, c, s in timeline],
        "ports": ports,
        "peers": peers,
        "ground_truth": {str(k): int(v) for k, v in truth.items() if k},
        "guidance": {
            "title": guidance.title, "technique": guidance.technique, "tactic": guidance.tactic,
            "description": guidance.description, "triage": guidance.triage,
        },
    })
    return payload


@router.patch("/incidents/{incident_id}", tags=["incidents"])
async def patch_incident(incident_id: int, patch: IncidentPatch, user: AnalystUser) -> dict:
    with session_scope() as sess:
        row = sess.get(Incident, incident_id)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident inconnu")
        changes = _apply_patch(row, patch, user.username)
        payload = incident_payload(row)
    Writer.audit(user.username, "incident.update", str(incident_id), changes)
    return payload


@router.post("/incidents/bulk", tags=["incidents"])
async def bulk_update(action: BulkAction, user: AnalystUser) -> dict:
    patch = IncidentPatch(status=action.status, assignee=action.assignee, verdict=action.verdict)
    updated = 0
    with session_scope() as sess:
        for row in sess.scalars(select(Incident).where(Incident.id.in_(action.ids))).all():
            _apply_patch(row, patch, user.username)
            updated += 1
    Writer.audit(user.username, "incident.bulk", f"{updated} incidents",
                 {"ids": action.ids[:50], "status": action.status, "verdict": action.verdict})
    return {"updated": updated}


def _apply_patch(row: Incident, patch: IncidentPatch, actor: str) -> dict:
    changes: dict[str, object] = {}
    if patch.status and patch.status != row.status:
        changes["status"] = [row.status, patch.status]
        row.status = patch.status
        row.closed_at = datetime.now(timezone.utc) if patch.status == "CLOSED" else None
    if patch.assignee is not None and patch.assignee != row.assignee:
        changes["assignee"] = [row.assignee, patch.assignee]
        row.assignee = patch.assignee
    if patch.verdict and patch.verdict != row.verdict:
        changes["verdict"] = [row.verdict, patch.verdict]
        row.verdict = patch.verdict
        # A judged incident is a closed incident: that is what makes the verdict
        # usable later as retraining signal.
        if row.status != "CLOSED":
            row.status = "CLOSED"
            row.closed_at = datetime.now(timezone.utc)
    if patch.note is not None:
        changes["note"] = True
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
        row.note = f"{row.note}\n\n[{stamp} {actor}] {patch.note}" if row.note else f"[{stamp} {actor}] {patch.note}"
    return changes


@router.get("/incidents/{incident_id}/export", tags=["incidents"])
async def export_incident(incident_id: int, user: CurrentUser) -> JSONResponse:
    payload = await get_incident(incident_id, user, alerts=1000)
    filename = f"aegis-incident-{incident_id}.json"
    return JSONResponse(payload, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ---------------------------------------------------------------------- hosts

@router.get("/hosts", tags=["hosts"])
async def list_hosts(user: CurrentUser, limit: int = Query(default=100, ge=1, le=1000),
                     q: str | None = None) -> dict:
    with session_scope() as sess:
        stmt = select(Host)
        if q:
            stmt = stmt.where(Host.ip.like(f"%{q}%") | Host.asset_name.like(f"%{q}%"))
        rows = sess.scalars(stmt.order_by(desc(Host.alerts), desc(Host.last_seen)).limit(limit)).all()
        items = [_host_payload(h) for h in rows]
        total = sess.scalar(select(func.count()).select_from(Host)) or 0
    return {"total": int(total), "items": items}


@router.get("/hosts/{ip}", tags=["hosts"])
async def get_host(ip: str, user: CurrentUser) -> dict:
    with session_scope() as sess:
        row = sess.get(Host, ip)
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "hôte inconnu")
        incidents = [
            incident_payload(i) for i in sess.scalars(
                select(Incident).where((Incident.src == ip) | (Incident.dst == ip))
                .order_by(desc(Incident.last_seen)).limit(50)
            ).all()
        ]
    payload = _host_payload(row)
    payload["incidents"] = incidents
    return payload


def _host_payload(h: Host) -> dict:
    return {
        "ip": h.ip, "asset_name": h.asset_name, "criticality": h.criticality,
        "first_seen": h.first_seen.isoformat() if h.first_seen else None,
        "last_seen": h.last_seen.isoformat() if h.last_seen else None,
        "flows_out": h.flows_out, "flows_in": h.flows_in,
        "bytes_out": h.bytes_out, "bytes_in": h.bytes_in,
        "alerts": h.alerts, "score_mean": round(h.score_mean, 4),
        "threshold": round(h.threshold, 4), "calibrated": h.calibrated,
    }


# ---------------------------------------------------------------------- model

@router.get("/model", tags=["model"])
async def model_info(request: Request, user: CurrentUser) -> dict:
    pipeline = _pipeline(request)
    meta = pipeline.model.meta
    return {
        "trained_at": meta.trained_at,
        "train_flows_benign": meta.train_flows_benign,
        "train_flows_labelled": meta.train_flows_labelled,
        "train_seeds": meta.train_seeds or [],
        "test_seeds": meta.test_seeds or [],
        "classes": meta.classes or [],
        "notes": meta.notes,
        "metrics": meta.metrics or {},
        "features": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "operating_point": {
            "base_threshold": settings.base_threshold,
            "min_threshold": settings.min_threshold,
            "max_threshold": settings.max_threshold,
            "host_quantile": settings.host_quantile,
            "baseline_min_samples": settings.baseline_min_samples,
            "supervised_min_confidence": settings.supervised_min_confidence,
        },
        "families": {
            k: {"title": v.title, "technique": v.technique, "tactic": v.tactic,
                "description": v.description, "triage": v.triage}
            for k, v in FAMILIES.items()
        },
    }


@router.get("/model/thresholds", tags=["model"])
async def thresholds(request: Request, user: CurrentUser,
                     limit: int = Query(default=60, ge=1, le=1000)) -> dict:
    pipeline = _pipeline(request)
    rows = pipeline.engine.thresholds.snapshot(limit=limit)
    return {"base": settings.base_threshold, "items": rows}


# ------------------------------------------------------------------- pipeline

@router.get("/pipeline", tags=["pipeline"])
async def pipeline_status(request: Request, user: CurrentUser) -> dict:
    return _pipeline(request).status()


@router.post("/pipeline/start", tags=["pipeline"])
async def pipeline_start(request: Request, user: AdminUser,
                         body: StartLab | StartPcap | StartLive) -> dict:
    # La validation de la requête passe avant tout accès au moteur : une requête
    # malformée doit être rejetée de la même façon qu'un modèle soit chargé ou
    # non. Sans cela, un chemin de traversée de répertoire recevait un 503
    # « aucun modèle » au lieu du 404 qu'il mérite — la faute était masquée par
    # l'état d'exécution.
    pcap: Path | None = None
    if isinstance(body, StartPcap):
        pcap = (settings.pcap_dir / Path(body.file).name).resolve()
        if not pcap.is_relative_to(settings.pcap_dir.resolve()) or not pcap.exists():
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                f"fichier PCAP introuvable : {body.file}")

    pipeline = _pipeline(request)
    if isinstance(body, StartLab):
        await pipeline.start_lab(duration=body.duration, speed=body.speed, seed=body.seed,
                                density=body.density, stealth_ratio=body.stealth_ratio)
    elif pcap is not None:
        await pipeline.start_pcap(pcap, speed=body.speed)
    else:
        await pipeline.start_live(body.iface, bpf=body.bpf)
    Writer.audit(user.username, "pipeline.start", body.source, body.model_dump())
    return pipeline.status()


@router.post("/pipeline/stop", tags=["pipeline"])
async def pipeline_stop(request: Request, user: AdminUser) -> dict:
    pipeline = _pipeline(request)
    await pipeline.stop()
    Writer.audit(user.username, "pipeline.stop")
    return pipeline.status()


@router.get("/pcaps", tags=["pipeline"])
async def list_pcaps(user: CurrentUser) -> dict:
    files = []
    for path in sorted(settings.pcap_dir.glob("*")):
        if path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
            files.append({"name": path.name, "size": path.stat().st_size,
                          "modified": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()})
    return {"directory": str(settings.pcap_dir), "items": files}


@router.post("/pcaps", tags=["pipeline"])
async def upload_pcap(user: AdminUser, file: UploadFile) -> dict:
    name = Path(file.filename or "capture.pcap").name
    if Path(name).suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "extension attendue : .pcap, .pcapng ou .cap")
    target = settings.pcap_dir / name
    size = 0
    with target.open("wb") as fh:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            fh.write(chunk)
    Writer.audit(user.username, "pcap.upload", name, {"bytes": size})
    return {"name": name, "size": size}


# ------------------------------------------------------------------- settings

@router.get("/settings", tags=["settings"])
async def get_settings(request: Request, user: CurrentUser) -> dict:
    pipeline = _pipeline(request)
    return {
        "detection": {
            "base_threshold": settings.base_threshold,
            "min_threshold": settings.min_threshold,
            "max_threshold": settings.max_threshold,
            "host_quantile": settings.host_quantile,
            "dedup_window": settings.dedup_window,
            "supervised_min_confidence": settings.supervised_min_confidence,
            "baseline_min_samples": settings.baseline_min_samples,
            "flow_idle_timeout": settings.flow_idle_timeout,
            "flow_syn_timeout": settings.flow_syn_timeout,
        },
        "assets": [
            {"cidr": a.cidr, "name": a.name, "criticality": a.criticality, "tags": a.tags}
            for a in pipeline.assets.all()
        ],
    }


@router.put("/settings/detection", tags=["settings"])
async def put_detection(body: DetectionSettingsIn, user: AdminUser) -> dict:
    if not (body.min_threshold <= body.base_threshold <= body.max_threshold):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "il faut min_threshold ≤ base_threshold ≤ max_threshold")
    for field, value in body.model_dump().items():
        setattr(settings, field, value)
    with session_scope() as sess:
        row = sess.get(Setting, "detection") or Setting(key="detection")
        row.value = body.model_dump()
        sess.add(row)
    Writer.audit(user.username, "settings.detection", detail=body.model_dump())
    return body.model_dump()


@router.put("/settings/assets", tags=["settings"])
async def put_assets(request: Request, body: AssetsIn, user: AdminUser) -> dict:
    pipeline = _pipeline(request)
    assets = [Asset(cidr=e.cidr, name=e.name, criticality=e.criticality, tags=e.tags)
              for e in body.entries]
    registry = AssetRegistry(assets)
    pipeline.assets = registry
    pipeline.correlator.assets = registry
    pipeline.engine.assets = registry
    with session_scope() as sess:
        row = sess.get(Setting, "assets") or Setting(key="assets")
        row.value = {"entries": [e.model_dump() for e in body.entries]}
        sess.add(row)
    Writer.audit(user.username, "settings.assets", f"{len(assets)} entrées")
    return {"count": len(assets)}


# ---------------------------------------------------------------------- audit

@router.get("/audit", tags=["audit"])
async def audit_log(user: AdminUser, limit: int = Query(default=200, ge=1, le=2000)) -> dict:
    with session_scope() as sess:
        rows = sess.scalars(select(AuditEntry).order_by(desc(AuditEntry.ts)).limit(limit)).all()
    return {"items": [
        {"id": r.id, "ts": r.ts.isoformat(), "actor": r.actor, "action": r.action,
         "target": r.target, "detail": r.detail}
        for r in rows
    ]}
