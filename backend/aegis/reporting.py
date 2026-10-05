"""Benchmark report generation: docs/BENCHMARK.md, written by `aegis train`.

The report is generated, never hand-written, so the numbers in the documentation
cannot drift away from the model that is actually on disk.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from aegis.config import REPO_ROOT, settings
from aegis.core.features import FEATURE_NAMES
from aegis.core.mitre import info as mitre_info


def write_benchmark(model, ev, path: Path | None = None) -> Path:
    path = path or REPO_ROOT / "docs" / "BENCHMARK.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    meta = model.meta
    st = ev.stealth or {}

    def pct(x) -> str:
        return f"{float(x) * 100:.2f} %"

    lines: list[str] = [
        "# Résultats de référence — AEGIS Mini-SOC",
        "",
        "> Fichier **généré** par `aegis train` / `aegis bench`. Ne pas éditer à la main :",
        "> il est réécrit à chaque entraînement pour qu'il décrive toujours le modèle",
        f"> réellement présent dans `{settings.stage_a_path.name}`.",
        "",
        f"- Modèle entraîné le : `{meta.trained_at}`",
        f"- Captures d'entraînement (seeds) : `{meta.train_seeds}`",
        f"- Captures de test (seeds) : `{meta.test_seeds}` — **disjoints**",
        f"- Flux bénins vus par l'étage A : {meta.train_flows_benign:,}",
        f"- Flux étiquetés vus par l'étage B : {meta.train_flows_labelled:,}",
        f"- Nombre de features : {len(FEATURE_NAMES)}",
        f"- Seuil plancher : {settings.base_threshold} (percentile du trafic bénin)",
        "",
        "## Protocole",
        "",
        "1. L'étage A (IsolationForest) n'est entraîné que sur du **trafic bénin**.",
        "2. L'étage B (HistGradientBoosting) est entraîné sur des captures étiquetées,",
        "   plafonnées par classe pour qu'une seule inondation ne représente pas la",
        "   majorité du jeu de données.",
        "3. La séparation train/test se fait **par capture** (par « journée simulée »),",
        "   jamais par ligne : des flux issus de la même rafale d'attaque sont très",
        "   corrélés, et un découpage aléatoire produirait des scores illusoires.",
        "4. Le point de fonctionnement est mesuré en **rejouant les captures de test",
        "   dans le moteur réel**, seuils adaptatifs compris, préchauffés sur une",
        "   capture bénigne comme le serait une sonde déployée.",
        "5. Les faux positifs sont mesurés sur des captures **sans aucune attaque**.",
        "",
        "## Détection",
        "",
        "| Mesure | Attaques bruyantes | Attaques furtives |",
        "|---|---|---|",
        f"| Rappel | {pct(ev.recall)} | {pct(st.get('recall', 0))} |",
        f"| Précision | {pct(ev.precision)} | {pct(st.get('precision', 0))} |",
        f"| F1 | {ev.f1:.4f} | {float(st.get('f1', 0)):.4f} |",
        f"| PR-AUC | {ev.pr_auc:.4f} | {float(st.get('pr_auc', 0)):.4f} |",
        f"| Latence médiane | {ev.latency_p50:.1f} s | {float(st.get('latency_p50', 0)):.1f} s |",
        f"| Latence p95 | {ev.latency_p95:.1f} s | {float(st.get('latency_p95', 0)):.1f} s |",
        "",
        f"- ROC-AUC (bruyant) : **{ev.roc_auc:.4f}**",
        f"- Matrice de confusion binaire : VP {ev.tp:,} · FP {ev.fp:,} · FN {ev.fn:,} · VN {ev.tn:,}",
        f"- Débit mesuré : **{ev.throughput_pkts_per_sec:,.0f} paquets/s** (mono-processus)",
        "",
        "### Pourquoi deux colonnes",
        "",
        "Les variantes « furtives » sont les mêmes attaques ralenties d'un facteur 15 à 60,",
        "avec rotation des sources, variation des tailles de requête et gigue de 25 % sur les",
        "balises. Les chiffres bruyants disent que la chaîne fonctionne ; les chiffres furtifs",
        "disent où elle cesse de fonctionner. Un rapport qui ne publie que la première colonne",
        "ne mesure pas un détecteur, il mesure un générateur de trafic.",
        "",
        "## Charge d'alerte sur trafic normal",
        "",
        f"- Flux bénins évalués : {ev.benign_flows:,}",
        f"- Part des flux bénins qui alertent : {pct(ev.benign_fp_rate)}",
        f"- **{ev.benign_alerts_per_hour:,.0f} alertes/heure** avant corrélation",
        f"- **{ev.benign_incidents_per_hour:.1f} incidents/heure** après corrélation",
        "",
        "La seconde valeur est celle qui compte : c'est le nombre de lignes de travail",
        "effectives pour un analyste. L'écart entre les deux est exactement ce que la",
        "corrélation apporte.",
        "",
        "## Rappel par famille d'attaque",
        "",
        "| Famille | MITRE | Rappel (bruyant) | Rappel (furtif) | n (bruyant) |",
        "|---|---|---|---|---|",
    ]
    stealth_recall = st.get("family_recall", {})
    for family, recall in sorted(ev.family_recall.items()):
        lines.append(
            f"| {family} | `{mitre_info(family).technique}` | {pct(recall)} | "
            f"{pct(stealth_recall.get(family, 0))} | {ev.family_support.get(family, 0):,} |"
        )

    lines += [
        "",
        "## Nommage de la famille (étage B)",
        "",
        f"macro-F1 : **{ev.classifier_macro_f1:.4f}** (bruyant) · "
        f"**{float(st.get('classifier_macro_f1', 0)):.4f}** (furtif)",
        "",
        "| Famille | Précision | Rappel | F1 | n |",
        "|---|---|---|---|---|",
    ]
    for family, m in ev.classifier_report.items():
        lines.append(f"| {family} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['support']:,} |")

    if ev.confusion:
        labels = ev.confusion["labels"]
        lines += ["", "### Matrice de confusion", "",
                  "| vérité \\ prédit | " + " | ".join(labels) + " |",
                  "|---" * (len(labels) + 1) + "|"]
        for i, row in enumerate(ev.confusion["matrix"]):
            name = labels[i] if i < len(labels) else "?"
            lines.append(f"| **{name}** | " + " | ".join(str(v) for v in row) + " |")

    lines += [
        "",
        "## Limites à connaître",
        "",
        "1. **Le trafic est synthétique.** La chaîne de détection (assemblage de flux,",
        "   features, modèle, seuils, corrélation) est réelle et c'est la même qui tourne",
        "   en production ; le trafic qui l'alimente est généré. Un vrai réseau est plus",
        "   désordonné : attendez-vous à davantage de faux positifs qu'ici.",
        "2. **Les familles sont séparables par construction.** Le générateur produit des",
        "   comportements paramétriques distincts, ce qui explique les scores très élevés",
        "   de l'étage B sur les variantes bruyantes. La colonne « furtive » est la mesure",
        "   honnête, et `aegis replay` sur un PCAP réel est la vraie épreuve.",
        "3. **La latence inclut le délai d'export des flux** (3 s pour une tentative de",
        "   connexion sans réponse, 15 s d'inactivité sinon, 120 s pour un flux long).",
        "   C'est le compromis inhérent à une détection par flux plutôt que par paquet.",
        "4. **Les sources usurpées** ne sont détectables que côté destination : c'est le",
        "   rôle des quatre features `dst_*`.",
        "",
        f"_Généré le {datetime.now(timezone.utc).isoformat(timespec='seconds')}._",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
