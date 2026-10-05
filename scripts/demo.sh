#!/usr/bin/env bash
# Démonstration complète d'AEGIS, de zéro à l'interface ouverte.
set -euo pipefail
cd "$(dirname "$0")/.."

say() { printf '\n\033[36m▸ %s\033[0m\n' "$1"; }

if [ ! -x backend/.venv/bin/python ]; then
  say "Installation des dépendances Python"
  python3 -m venv backend/.venv
  backend/.venv/bin/pip install -q --upgrade pip
  backend/.venv/bin/pip install -q -e "backend[dev]"
fi

if [ ! -d frontend/node_modules ]; then
  say "Installation des dépendances de l'interface"
  (cd frontend && npm install --cache "$PWD/../.npm-cache")
fi

if [ ! -d frontend/dist ]; then
  say "Compilation de l'interface"
  (cd frontend && npm run build)
fi

if [ ! -f data/models/stage_a_isoforest.joblib ]; then
  say "Entraînement du modèle (environ 6 minutes, une seule fois)"
  (cd backend && PYTHONPATH=. .venv/bin/python -m aegis.cli train --duration 600 --captures 6)
fi

if [ ! -f data/aegis.db ]; then
  say "Création de la base et des comptes"
  (cd backend && PYTHONPATH=. .venv/bin/python -m aegis.cli init)
fi

PORT="${AEGIS_PORT:-8000}"

# Refuser de démarrer par-dessus une instance existante : uvicorn échoue sinon
# sur un « address already in use » qui n'explique rien à personne.
if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  if curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
    say "AEGIS tourne déjà sur le port $PORT"
    echo "  Interface : http://127.0.0.1:$PORT"
    echo
    echo "  Pour la remplacer par une instance neuve :"
    echo "    pkill -f 'aegis.cli serve' && ./scripts/demo.sh"
    echo "  Ou pour en lancer une seconde sur un autre port :"
    echo "    AEGIS_PORT=8001 ./scripts/demo.sh"
    exit 0
  fi
  say "Le port $PORT est déjà occupé par un autre service"
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN | sed 's/^/  /'
  echo
  echo "  Choisissez un autre port :  AEGIS_PORT=8001 ./scripts/demo.sh"
  exit 1
fi

say "Démarrage de l'API avec le réseau de laboratoire"
echo "  Interface : http://127.0.0.1:$PORT"
echo "  API       : http://127.0.0.1:$PORT/docs"
echo "  Ctrl-C pour arrêter."
cd backend
AEGIS_AUTOSTART=lab AEGIS_AUTOSTART_SPEED=6 PYTHONPATH=. \
  exec .venv/bin/python -m aegis.cli serve --port "$PORT"
