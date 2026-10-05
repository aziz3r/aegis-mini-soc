#!/usr/bin/env bash
# Convertit les schémas en PDF puis compile les deux documents LaTeX.
#
# Les schémas vivent en SVG pour le README (deux variantes, claire et sombre) ;
# LaTeX ne sait pas les inclure, d'où la conversion de la variante claire.
set -euo pipefail
cd "$(dirname "$0")/.."

say() { printf '\n\033[36m▸ %s\033[0m\n' "$1"; }

command -v tectonic >/dev/null || {
  echo "tectonic est requis :  brew install tectonic" >&2; exit 1; }

say "Régénération des schémas"
(cd docs/schemas && ../../backend/.venv/bin/python tout.py)

say "Conversion des schémas en PDF"
backend/.venv/bin/python - <<'PY'
import pathlib
import cairosvg
for svg in sorted(pathlib.Path("docs").glob("*.svg")):
    if svg.stem.endswith("-dark"):
        continue                      # le PDF est imprimé : la variante claire suffit
    cairosvg.svg2pdf(url=str(svg), write_to=str(svg.with_suffix(".pdf")))
    print(f"  ✔ {svg.stem}.pdf")
PY

say "Compilation des documents"
cd rapport
for doc in rapport_projet dossier_technique; do
  tectonic -X compile "$doc.tex" --outdir . >/dev/null 2>&1
  pages=$(../backend/.venv/bin/python -c "from pypdf import PdfReader;print(len(PdfReader('$doc.pdf').pages))")
  printf '  ✔ %-22s %s pages, %s Kio\n' "$doc.pdf" "$pages" "$(( $(stat -f %z "$doc.pdf") / 1024 ))"
done
