# Rapport et dossier technique

| Fichier | Contenu |
|---|---|
| `rapport_projet.pdf` | **Le rapport** (9 pages) — introduction, architecture, moteur de détection, corrélation, interface avec captures, résultats, difficultés rencontrées, limites. |
| `dossier_technique.pdf` | Dossier complémentaire (14 pages) — spécification exhaustive : les 52 caractéristiques, les deux étages, le seuil adaptatif, le protocole de mesure, les résultats famille par famille, le modèle de données, l'inventaire des tests. |

Sources LaTeX : `rapport_projet.tex`, `dossier_technique.tex`, `preambule.tex` (commun).

## Recompiler

```bash
brew install tectonic          # moteur LaTeX autonome, sans privilèges
make pdf                       # convertit les schémas puis compile les deux documents
```

Ou à la main :

```bash
cd rapport
tectonic -X compile rapport_projet.tex
tectonic -X compile dossier_technique.tex
```

Les figures proviennent de `../docs/` : les schémas sont les versions PDF engendrées depuis les
mêmes descriptions que les SVG du README (`docs/schemas/`), et les captures sont celles de
l'application en fonctionnement.
