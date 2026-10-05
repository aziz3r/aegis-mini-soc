"""`aegis` command line.

    aegis init                 create the database and the default accounts
    aegis train                train both stages and write the model + benchmark
    aegis bench                re-evaluate the saved model, refresh the benchmark
    aegis dataset              export a labelled dataset as .npz
    aegis serve                run the API (and the web UI's backend)
    aegis export-pcap          write lab traffic to a .pcap file
    aegis replay FILE.pcap     replay a capture file through the live pipeline
    aegis capture IFACE        capture live traffic (requires root)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis import __version__
from aegis.config import settings


def _p(msg: str = "") -> None:
    print(msg, flush=True)


# ------------------------------------------------------------------- commands

def cmd_init(args: argparse.Namespace) -> int:
    from aegis.store.db import init_db
    from aegis.store.seed import seed_defaults

    init_db(drop=args.reset)
    created = seed_defaults(admin_password=args.admin_password)
    _p(f"Base de données prête : {settings.database_url}")
    for line in created:
        _p(f"  {line}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    from aegis.ml.train import train_and_evaluate
    from aegis.reporting import write_benchmark

    train_seeds = args.train_seeds or list(range(11, 11 + args.captures))
    test_seeds = args.test_seeds or list(range(901, 901 + max(args.captures // 2, 2)))
    _p(f"AEGIS {__version__} — entraînement")
    _p(f"  captures d'entraînement : {train_seeds}")
    _p(f"  captures de test        : {test_seeds}  (seeds disjoints)")
    _p(f"  durée par capture       : {args.duration:.0f}s")
    _p("")
    model, ev = train_and_evaluate(train_seeds, test_seeds, args.duration, args.density, progress=_p)
    path = model.save()
    _p(f"\nModèle écrit : {path}")
    report = write_benchmark(model, ev)
    _p(f"Rapport      : {report}")
    _p("")
    _p(_summary(ev))
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from aegis.ml.model import DetectionModel
    from aegis.ml.train import evaluate
    from aegis.reporting import write_benchmark

    model = DetectionModel.load()
    seeds = args.test_seeds or [901, 902, 903]
    _p(f"Évaluation du modèle entraîné le {model.meta.trained_at} sur les seeds {seeds}")
    ev = evaluate(model, seeds, args.duration, args.density, progress=_p)
    stealth = evaluate(model, seeds, args.duration, args.density, stealth_ratio=1.0, progress=_p)
    ev.stealth = {
        "precision": stealth.precision, "recall": stealth.recall, "f1": stealth.f1,
        "pr_auc": stealth.pr_auc, "family_recall": stealth.family_recall,
        "family_support": stealth.family_support,
        "classifier_macro_f1": stealth.classifier_macro_f1,
        "latency_p50": stealth.latency_p50, "latency_p95": stealth.latency_p95,
        "incidents": stealth.incidents, "alerts": stealth.alerts,
    }
    model.meta.metrics = ev.as_dict()
    model.save()
    _p(f"Rapport : {write_benchmark(model, ev)}")
    _p("")
    _p(_summary(ev))
    return 0


def cmd_dataset(args: argparse.Namespace) -> int:
    from aegis.ml.dataset import save_npz, simulate_capture, stack

    seeds = args.seeds or [1, 2, 3]
    caps = [simulate_capture(s, args.duration, benign_only=args.benign_only,
                             stealth_ratio=args.stealth_ratio) for s in seeds]
    X, y = stack(caps)
    out = Path(args.out) if args.out else settings.dataset_dir / "lab.npz"
    save_npz(out, X, y)
    counts: dict[str, int] = {}
    for label in y:
        counts[str(label)] = counts.get(str(label), 0) + 1
    _p(f"{len(X):,} flux x {X.shape[1]} features -> {out}")
    _p(json.dumps(counts, indent=2, ensure_ascii=False))
    return 0


def cmd_export_pcap(args: argparse.Namespace) -> int:
    from aegis.sources.lab import LabNetwork
    from aegis.sources.pcap_writer import write_pcap

    net = LabNetwork(seed=args.seed)
    plan = net.plan(args.duration, density=args.density, stealth_ratio=args.stealth_ratio)
    out = Path(args.out) if args.out else settings.pcap_dir / f"lab-{args.seed}-{int(args.duration)}s.pcap"
    _p(f"Génération de {args.duration:.0f}s de trafic (graine {args.seed}, {len(plan)} attaques)…")
    for spec in plan:
        _p(f"  {spec.family:<16} t+{spec.start:>6.0f}s  pendant {spec.duration:>5.0f}s"
           f"  {'furtif' if spec.stealth else 'bruyant'}")
    count, path = write_pcap(out, net.generate(args.duration, plan), progress=_p)
    size = path.stat().st_size
    _p(f"\n{count:,} paquets -> {path}  ({size / 1024 / 1024:.1f} Mio)")
    _p(f"Rejouez-le :  aegis replay {path.name} --speed 20")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    _p(f"AEGIS {__version__} — API sur http://{args.host}:{args.port}")
    _p(f"  documentation interactive : http://{args.host}:{args.port}/docs")
    uvicorn.run("aegis.api.app:app", host=args.host, port=args.port,
                reload=args.reload, log_level=args.log_level)
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    import asyncio

    from aegis.api.pipeline import Pipeline
    from aegis.ml.model import DetectionModel

    path = Path(args.pcap)
    if not path.exists():
        _p(f"Fichier introuvable : {path}")
        return 2
    pipeline = Pipeline(DetectionModel.load())

    async def run() -> None:
        await pipeline.start_pcap(path, speed=args.speed)
        while pipeline.is_running:
            await asyncio.sleep(0.5)
        await pipeline.stop()

    asyncio.run(run())
    _p(json.dumps(pipeline.status(), indent=2, ensure_ascii=False))
    return 0


def cmd_capture(args: argparse.Namespace) -> int:
    import asyncio

    from aegis.api.pipeline import Pipeline
    from aegis.ml.model import DetectionModel

    pipeline = Pipeline(DetectionModel.load())

    async def run() -> None:
        await pipeline.start_live(args.iface, bpf=args.filter)
        try:
            while pipeline.is_running:
                await asyncio.sleep(1.0)
        except KeyboardInterrupt:
            pass
        await pipeline.stop()

    _p(f"Capture sur {args.iface} (Ctrl-C pour arrêter). Nécessite les privilèges root.")
    asyncio.run(run())
    return 0


# -------------------------------------------------------------------- helpers

def _summary(ev) -> str:
    lines = [
        "┌─ RÉSULTATS ────────────────────────────────────────────────────────",
        f"│ Détection (attaques bruyantes)   rappel {ev.recall*100:6.2f}%   précision {ev.precision*100:6.2f}%   F1 {ev.f1:.4f}",
        f"│ Détection (attaques furtives)    rappel {ev.stealth.get('recall',0)*100:6.2f}%   précision {ev.stealth.get('precision',0)*100:6.2f}%   F1 {ev.stealth.get('f1',0):.4f}",
        f"│ Classement                       PR-AUC {ev.pr_auc:.4f}   ROC-AUC {ev.roc_auc:.4f}",
        f"│ Nommage des familles             macro-F1 {ev.classifier_macro_f1:.4f}",
        f"│ Faux positifs (trafic normal)    {ev.benign_alerts_per_hour:7.0f} alertes/h  →  {ev.benign_incidents_per_hour:5.1f} incidents/h",
        f"│ Latence de détection             p50 {ev.latency_p50:5.1f}s   p95 {ev.latency_p95:6.1f}s",
        f"│ Débit                            {ev.throughput_pkts_per_sec:,.0f} paquets/s",
        "└────────────────────────────────────────────────────────────────────",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="aegis", description=f"AEGIS Mini-SOC {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="créer la base et les comptes par défaut")
    p.add_argument("--reset", action="store_true", help="supprimer les tables existantes")
    p.add_argument("--admin-password", default=None)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("train", help="entraîner les deux étages")
    p.add_argument("--duration", type=float, default=600.0, help="secondes simulées par capture")
    p.add_argument("--captures", type=int, default=6, help="nombre de captures d'entraînement")
    p.add_argument("--density", type=float, default=1.0, help="densité d'attaques")
    p.add_argument("--train-seeds", type=int, nargs="*", default=None)
    p.add_argument("--test-seeds", type=int, nargs="*", default=None)
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("bench", help="réévaluer le modèle sauvegardé")
    p.add_argument("--duration", type=float, default=600.0)
    p.add_argument("--density", type=float, default=1.0)
    p.add_argument("--test-seeds", type=int, nargs="*", default=None)
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("dataset", help="exporter un jeu de données étiqueté")
    p.add_argument("--duration", type=float, default=600.0)
    p.add_argument("--seeds", type=int, nargs="*", default=None)
    p.add_argument("--benign-only", action="store_true")
    p.add_argument("--stealth-ratio", type=float, default=0.0)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_dataset)

    p = sub.add_parser("export-pcap", help="écrire du trafic de laboratoire dans un .pcap")
    p.add_argument("--duration", type=float, default=600.0)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--density", type=float, default=1.0)
    p.add_argument("--stealth-ratio", type=float, default=0.3)
    p.add_argument("--out", default=None)
    p.set_defaults(func=cmd_export_pcap)

    p = sub.add_parser("serve", help="lancer l'API")
    p.add_argument("--host", default=settings.host)
    p.add_argument("--port", type=int, default=settings.port)
    p.add_argument("--reload", action="store_true")
    p.add_argument("--log-level", default="info")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("replay", help="rejouer un fichier PCAP")
    p.add_argument("pcap")
    p.add_argument("--speed", type=float, default=0.0, help="0 = aussi vite que possible")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("capture", help="capturer le trafic réel (root)")
    p.add_argument("iface")
    p.add_argument("--filter", default="ip", help="filtre BPF")
    p.set_defaults(func=cmd_capture)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        _p("\ninterrompu")
        return 130
    except FileNotFoundError as exc:
        _p(f"Fichier manquant : {exc}")
        return 2
    except ValueError as exc:
        _p(f"Erreur : {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
