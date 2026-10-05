#!/usr/bin/env python3
"""Publie le dépôt via l'API Git Data de GitHub, sans passer par git.

Pourquoi : sur certaines machines (disque saturé, mémoire contrainte),
`pack-objects` devient instable — il meurt en SIGBUS ou met des minutes sur
quelques mégaoctets. Toute opération git qui empaquette devient alors
impraticable, y compris `git push`.

Ce script lit les fichiers sur le disque et construit directement les objets
chez GitHub : un blob par fichier, un arbre par commit, puis les commits
chaînés. L'historique reste découpé en étapes qui racontent l'architecture.
"""
from __future__ import annotations

import base64
import json
import mimetypes
import pathlib
import sys
import time
import urllib.error
import urllib.request

DEPOT = "aziz3r/aegis-mini-soc"
BRANCHE = "main"
API = "https://api.github.com"
RACINE = pathlib.Path(__file__).resolve().parents[1]

AUTEUR = {"name": "aziz3r", "email": "170641009+aziz3r@users.noreply.github.com"}

#: L'historique, dans l'ordre. Chaque étape liste des préfixes de chemin ;
#: un fichier appartient à la première étape qui le réclame.
ETAPES: list[tuple[list[str], str, str]] = [
    (
        [".gitignore", "LICENSE", "Makefile", ".env.example",
         "backend/pyproject.toml", "scripts/demo.sh"],
        "chore: project skeleton, tooling and licence",
        "One-command setup via scripts/demo.sh: no Docker, no database daemon, no\n"
        "root. SQLite by default, PostgreSQL by URL switch.",
    ),
    (
        ["backend/aegis/__init__.py", "backend/aegis/config.py",
         "backend/aegis/core/__init__.py", "backend/aegis/core/types.py",
         "backend/aegis/core/windows.py"],
        "feat(core): shared types and incremental sliding windows",
        "Everything upstream normalises into Packet; everything downstream consumes Flow\n"
        "and Verdict.\n\n"
        "The windows keep their aggregates incrementally rather than recomputing them per\n"
        "exported flow. The naive version was O(n * w) and collapsed exactly when it\n"
        "mattered most: during a flood one host holds thousands of records in its 60s\n"
        "window, which is precisely when flows arrive fastest.",
    ),
    (
        ["backend/aegis/core/features.py"],
        "feat(core): 52 features, and one deliberate omission",
        "33 intrinsic to the flow, 15 on source-host behaviour over 10s and 60s windows,\n"
        "and 4 on the destination host.\n\n"
        "The last four earn their place: a flood with spoofed source addresses is\n"
        "invisible from the source side, since each forged address sends a single packet.\n"
        "Only aggregating on the victim makes it detectable.\n\n"
        "The raw destination port is deliberately excluded. A tree model would memorise\n"
        "the lab's port numbers - 22 for SSH brute force, 53 for DNS tunnelling - and\n"
        "report excellent scores unrelated to its ability to generalise.",
    ),
    (
        ["backend/aegis/core/flows.py"],
        "feat(core): packet-to-flow assembly with lazy expiry heaps",
        "Bidirectional 5-tuple flows driven by the packet clock, never wall time, so a\n"
        "PCAP replayed at x60 yields the same flows as the original capture.\n\n"
        "Expiry uses lazy deadline heaps rather than scanning the active table: scanning\n"
        "was O(active flows) per packet and degraded precisely under flood and slowloris\n"
        "traffic, where thousands of concurrent flows is the whole point. 12k -> 33k pkt/s,\n"
        "and the equivalence with the naive scan is proven by a test rather than assumed.\n\n"
        "An unanswered SYN is exported after 3s instead of 15s. It is already a complete\n"
        "observation, and the long timeout added 15 seconds to the detection of every scan\n"
        "and flood - the two attacks made almost entirely of unanswered SYNs.",
    ),
    (
        ["backend/aegis/ml/__init__.py", "backend/aegis/ml/dataset.py",
         "backend/aegis/ml/model.py"],
        "feat(ml): two-stage model with ECDF calibration and occlusion attribution",
        "Stage A (IsolationForest) is trained on benign traffic only, so it can flag an\n"
        "attack it has never seen. Its raw score is meaningless on its own, so it is pushed\n"
        "through the empirical CDF of benign traffic: 0.97 then reads as 'more unusual than\n"
        "97% of known normal traffic', and a threshold on that number is interpretable.\n\n"
        "Stage B (HistGradientBoosting) names the family and declines below a confidence\n"
        "floor - a confident wrong label is worse for an analyst than no label.\n\n"
        "Explanation is occlusion attribution: each feature is replaced in turn by its\n"
        "benign median and the flow re-scored. Same intuition SHAP formalises, computed\n"
        "exactly for one-feature subsets, in one batched call, with no extra dependency.\n\n"
        "The dataset splits by capture, never by row: flows from the same attack burst are\n"
        "highly correlated, and a random row split yields the 99.9% that collapses on\n"
        "contact with real traffic.",
    ),
    (
        ["backend/aegis/ml/threshold.py"],
        "feat(ml): per-host adaptive threshold",
        "A single global threshold cannot fit every machine: a backup server that talks to\n"
        "twelve hosts at 3am and a receptionist's laptop do not share a normal.\n\n"
        "The textbook robust rule, median + k*MAD, was tried first and destroyed recall -\n"
        "down to 14%. Stage A scores are already percentiles, so on normal traffic they are\n"
        "near-uniform: median ~0.52, MAD ~0.24, and 0.52 + 4*1.4826*0.24 ~ 1.94 clamped to\n"
        "the ceiling for every host. MAD assumes a tight core with rare outliers; a uniform\n"
        "distribution has neither.\n\n"
        "A quantile of the host's own scores is the right statistic in a percentile space,\n"
        "and reads directly as a false-positive budget. Only non-alerting scores feed the\n"
        "baseline, so a host under sustained attack cannot normalise its own attack traffic\n"
        "and go quiet - the boiling-frog failure, and how a patient attacker beats naive\n"
        "adaptation.",
    ),
    (
        ["backend/aegis/ml/train.py", "backend/aegis/reporting.py"],
        "feat(ml): training and an honest measurement protocol",
        "Stage A is fitted on benign-only captures; stage B on labelled ones, class-capped\n"
        "so a single flood does not become 70% of the training set.\n\n"
        "The operating point is measured by replaying test captures through the real\n"
        "Engine, adaptive thresholds included, warmed up on a benign capture as a deployed\n"
        "sensor would be - not by thresholding a score column offline.\n\n"
        "False positives are measured on attack-free captures, because precision computed\n"
        "on an attack-heavy capture flatters any detector. Latency is counted to the first\n"
        "alert including the flow export delay, because that delay is real.\n\n"
        "docs/BENCHMARK.md is generated, so the documentation cannot describe a model other\n"
        "than the one actually on disk.",
    ),
    (
        ["backend/aegis/core/engine.py"],
        "feat(core): detection engine and the precision cascade",
        "Packets in, verdicts out. Both the live pipeline and the offline benchmark drive\n"
        "this same class through the same code path - deliberately, so a benchmark number\n"
        "cannot describe a system different from the one that runs.\n\n"
        "The cascade: when stage A flags a marginal flow that stage B recognises as normal\n"
        "with >=90% confidence, the alert is suppressed - but never above 0.9975, where a\n"
        "strong anomaly always alerts whatever the classifier says. That boundary is what\n"
        "preserves detection of attacks never seen in training.\n\n"
        "Measured: 341 -> 53 false positives per hour, for 0.6 points of stealth recall.\n\n"
        "The threshold is read before the score feeds the baseline, so a flow can never\n"
        "influence the threshold it is judged against.",
    ),
    (
        ["backend/aegis/core/correlate.py", "backend/aegis/core/mitre.py",
         "backend/aegis/core/assets.py"],
        "feat(core): incident correlation, MITRE mapping and asset criticality",
        "A flood produces thousands of alerting flows per minute. Showing them one by one\n"
        "is how a SOC drowns - the failure has a name, alert fatigue, and it is why\n"
        "analysts stop reading dashboards.\n\n"
        "The grouping key follows the shape of the attack: one-to-many groups on the\n"
        "source, many-to-one on the victim, one-to-one on the pair. Measured live: 8,994\n"
        "alerts collapse into one incident.\n\n"
        "Severity is not the score. It is the margin above that host's threshold, weighted\n"
        "by what the targeted asset is worth and by classifier confidence - so a port scan\n"
        "against the database server outranks a louder scan against a printer.\n\n"
        "Each family carries its MITRE ATT&CK technique and a triage note written for an\n"
        "analyst: 'score 0.93' is not actionable, 'T1046, check whether the source is an\n"
        "authorised scanner' is.",
    ),
    (
        ["backend/aegis/sources/__init__.py", "backend/aegis/sources/lab.py"],
        "feat(sources): synthetic lab network with ground-truth labels",
        "A detector is worthless without an honest measurement, and an honest measurement\n"
        "needs labels. Capturing a real network gives traffic but no labels; the public IDS\n"
        "datasets are flow-level only and cannot exercise a packet-level pipeline.\n\n"
        "So this generates packets. Every packet carries its family, and it is fed through\n"
        "exactly the same FlowTable and feature extractor as a real capture: the traffic is\n"
        "synthetic, the detection chain is real.\n\n"
        "Nine attack families plus a stealth variant of each - slowed 15 to 60 times, with\n"
        "source rotation and 25% jitter on beacons. The loud numbers say the pipeline\n"
        "works; the stealth numbers say where it stops working.",
    ),
    (
        ["backend/aegis/sources/stream.py", "backend/aegis/sources/pcap_reader.py",
         "backend/aegis/sources/pcap_writer.py"],
        "feat(sources): native PCAP reader/writer and live capture",
        "Three sources behind one interface, so the engine cannot tell them apart.\n\n"
        "PCAP decoding is a direct struct reader: scapy managed 3,200 pkt/s, which made\n"
        "replaying a million-packet capture a five-minute wait before the first flow.\n"
        "99,000 pkt/s now, with scapy kept as the fallback for link types the fast path\n"
        "does not handle.\n\n"
        "The writer uses a snaplen that still retains the whole payload sample, so byte\n"
        "counters and entropy survive the round trip exactly - verified byte-for-byte by a\n"
        "test, because otherwise no measurement taken on a capture would describe the\n"
        "deployed system.\n\n"
        "The lab source builds traffic in 600s chunks: planning a whole day up front meant\n"
        "half a million session generators before the first packet, and API startup hung.",
    ),
    (
        ["backend/aegis/store/", "backend/aegis/api/", "backend/aegis/cli.py"],
        "feat(api): FastAPI with WebSocket streaming, JWT roles and an audit trail",
        "One asyncio task owns the whole detection path - engine, correlator and writer -\n"
        "which removes every lock and every race. Database flushes run in a thread\n"
        "executor; leaving them on the event loop froze the API for the duration of each\n"
        "commit.\n\n"
        "A slow WebSocket subscriber must never slow ingestion: each subscriber owns a\n"
        "bounded queue and drops its oldest events. Dropping frames for one browser tab\n"
        "beats stalling packet capture for everyone.\n\n"
        "Three server-enforced roles, scrypt password hashing from the standard library -\n"
        "one less dependency, no passlib/bcrypt version drift - and an audit entry for\n"
        "every state change, without which triage is not verifiable.\n\n"
        "Alerts are appended per incident up to a cap: keeping the ten-thousandth identical\n"
        "SYN of a flood has no investigative value and would grow the database without\n"
        "bound. The occurrence counter still tells the whole story.",
    ),
    (
        ["frontend/"],
        "feat(web): React SOC interface, eight screens",
        "TypeScript strict throughout. Live updates over WebSocket, buffered and published\n"
        "at 4 Hz so a flood cannot make the page stutter exactly when the operator needs it\n"
        "most.\n\n"
        "Chart colours were validated with a colour-vision-deficiency checker rather than\n"
        "chosen by eye: the whole application uses two series colours, both passing every\n"
        "check against the dark surface. Severity is status, not a series - red, orange and\n"
        "yellow are hue neighbours, so severity always ships with an icon and a label.\n\n"
        "The main chart plots the mean score, not the per-second maximum: scores are\n"
        "percentiles, so the maximum of N flows sits above 0.95 in 58% of seconds with\n"
        "nothing wrong. A chart pinned to its ceiling teaches operators to ignore it.\n\n"
        "No chart uses a dual axis.",
    ),
    (
        ["backend/tests/"],
        "test: 94 tests across engine, detection, API and PCAP round-trip",
        "Notable coverage:\n"
        "- the optimised flow expiry is proven equivalent to the naive scan over 240s of\n"
        "  mixed traffic, rather than assumed;\n"
        "- the calibrator recovers the normal CDF to +/-0.01;\n"
        "- the boiling-frog guard: 5,000 alerting scores do not move a host's threshold;\n"
        "- correlation grouping per attack shape - scan to one incident, flood to one,\n"
        "  two brute-force sources to two;\n"
        "- the PCAP round trip is byte-for-byte, structural features 100% identical;\n"
        "- the real database write path, because a bug lived there: SQLAlchemy applies\n"
        "  column defaults at INSERT, so a freshly built row still held None and the first\n"
        "  += killed the ingest task, silently.",
    ),
    (
        ["docs/", "README.md", "rapport/", "scripts/"],
        "docs: README français, schémas SVG, rapports LaTeX et démonstration",
        "README en français : titre centré, badges, démonstration de 40 secondes en tête,\n"
        "tableau de captures, sections dépliables, choses apprises en chemin, limites\n"
        "assumées.\n\n"
        "Cinq schémas en SVG, variantes claire et sombre, engendrés par des scripts Python\n"
        "depuis une description unique - ce qui empêche les deux variantes de diverger - et\n"
        "un vérificateur refuse qu'un texte déborde de sa toile, pour qu'un schéma ne\n"
        "vieillisse pas en silence pendant que le projet avance.\n\n"
        "Deux documents LaTeX compilés par tectonic : le rapport de projet (9 pages) et le\n"
        "dossier technique (14 pages).\n\n"
        "DECISIONS.md recense les bugs qui ont réellement changé le système et ce que\n"
        "chacun a appris - le seuil MAD, le parcours en O(n), la latence mesurée sur la\n"
        "mauvaise horloge, des trames déclarant moins d'octets qu'elles n'en portaient.",
    ),
    (
        [".github/", "CONTRIBUTING.md"],
        "ci: intégration continue et guide de contribution",
        "Cinq travaux : tests rapides, suite complète, interface (types stricts puis\n"
        "compilation), schémas, sécurité (gitleaks et pip-audit).\n\n"
        "Le travail « schémas » régénère les SVG et refuse un envoi où les fichiers\n"
        "versionnés ne correspondraient plus à leurs générateurs.\n\n"
        "CONTRIBUTING.md décrit la stratégie de branches et les deux cas qui invalident des\n"
        "artefacts : toucher à FEATURE_NAMES oblige à réentraîner, toucher à un schéma\n"
        "oblige à le régénérer.",
    ),
]

TEXTE = {".py", ".ts", ".tsx", ".md", ".txt", ".json", ".yml", ".yaml", ".toml",
         ".sh", ".css", ".html", ".svg", ".tex", ".example", ".gitignore", ".js"}


class Api:
    def __init__(self, jeton: str) -> None:
        self.jeton = jeton
        self.appels = 0

    def __call__(self, chemin: str, corps: dict | None = None, methode: str = "GET") -> dict:
        url = f"{API}/{chemin.lstrip('/')}"
        donnees = json.dumps(corps).encode() if corps is not None else None
        requete = urllib.request.Request(url, data=donnees, method=methode, headers={
            "Authorization": f"Bearer {self.jeton}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "aegis-publisher",
        })
        for essai in range(5):
            try:
                with urllib.request.urlopen(requete, timeout=120) as reponse:
                    self.appels += 1
                    return json.loads(reponse.read() or b"{}")
            except urllib.error.HTTPError as err:
                if err.code in (403, 429, 500, 502, 503) and essai < 4:
                    time.sleep(3 * (essai + 1))
                    continue
                raise RuntimeError(f"{methode} {chemin} -> {err.code} {err.read()[:300]!r}") from err
            except urllib.error.URLError:
                if essai < 4:
                    time.sleep(3 * (essai + 1))
                    continue
                raise
        raise RuntimeError("échec après 5 tentatives")


def est_binaire(chemin: pathlib.Path) -> bool:
    if chemin.suffix.lower() in TEXTE:
        return False
    type_mime, _ = mimetypes.guess_type(chemin.name)
    return not (type_mime or "").startswith("text/")


def main() -> int:
    jeton = pathlib.Path(sys.argv[1]).read_text().strip()
    liste = pathlib.Path(sys.argv[2]).read_text().split()
    api = Api(jeton)

    restants = sorted(liste)
    groupes: list[tuple[list[str], str, str]] = []
    for prefixes, titre, corps in ETAPES:
        pris = [f for f in restants
                if any(f == p or f.startswith(p) for p in prefixes)]
        restants = [f for f in restants if f not in set(pris)]
        if pris:
            groupes.append((pris, titre, corps))
    if restants:                       # rien ne doit être oublié
        groupes[-1][0].extend(restants)
        print(f"  ({len(restants)} fichier(s) rattaché(s) à la dernière étape)")

    print(f"{sum(len(g[0]) for g in groupes)} fichiers en {len(groupes)} commits\n")

    parent: str | None = None
    arbre_base: str | None = None
    for numero, (fichiers, titre, corps) in enumerate(groupes, 1):
        elements = []
        for nom in fichiers:
            chemin = RACINE / nom
            octets = chemin.read_bytes()
            if est_binaire(chemin):
                blob = api(f"repos/{DEPOT}/git/blobs", {
                    "content": base64.b64encode(octets).decode(), "encoding": "base64"}, "POST")
                elements.append({"path": nom, "mode": "100644", "type": "blob",
                                 "sha": blob["sha"]})
            else:
                mode = "100755" if chemin.suffix == ".sh" or (chemin.stat().st_mode & 0o111) else "100644"
                elements.append({"path": nom, "mode": mode, "type": "blob",
                                 "content": octets.decode("utf-8")})
        corps_arbre: dict = {"tree": elements}
        if arbre_base:
            corps_arbre["base_tree"] = arbre_base
        arbre = api(f"repos/{DEPOT}/git/trees", corps_arbre, "POST")
        arbre_base = arbre["sha"]

        horodatage = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
        corps_commit: dict = {
            "message": f"{titre}\n\n{corps}\n",
            "tree": arbre["sha"],
            "author": {**AUTEUR, "date": horodatage},
            "committer": {**AUTEUR, "date": horodatage},
        }
        if parent:
            corps_commit["parents"] = [parent]
        commit = api(f"repos/{DEPOT}/git/commits", corps_commit, "POST")
        parent = commit["sha"]
        print(f"  {numero:2d}/{len(groupes)}  {commit['sha'][:7]}  {len(fichiers):3d} fichiers  {titre[:50]}")

    api(f"repos/{DEPOT}/git/refs/heads/{BRANCHE}",
        {"sha": parent, "force": True}, "PATCH")
    print(f"\n{BRANCHE} -> {parent[:7]}   ({api.appels} appels d'API)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
