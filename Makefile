# AEGIS Mini-SOC — raccourcis de développement et d'exploitation.
# Tout passe par le venv du backend : aucune dépendance installée globalement.

PY       := backend/.venv/bin/python
PIP      := backend/.venv/bin/pip
AEGIS    := cd backend && PYTHONPATH=. .venv/bin/python -m aegis.cli
NPM_CACHE?= $(CURDIR)/.npm-cache

.DEFAULT_GOAL := help
.PHONY: help setup backend-setup frontend-setup train bench init serve dev build test test-fast lint demo replay clean reset pdf schemas

help: ## Afficher cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: backend-setup frontend-setup ## Installer toutes les dépendances

backend-setup: ## Créer le venv Python et installer les dépendances
	python3 -m venv backend/.venv
	$(PIP) install -q --upgrade pip
	$(PIP) install -q -e "backend[dev]"
	@echo "backend prêt"

frontend-setup: ## Installer les dépendances npm
	cd frontend && npm install --cache "$(NPM_CACHE)"
	@echo "frontend prêt"

init: ## Créer la base de données et les comptes par défaut
	$(AEGIS) init

reset: ## Repartir d'une base vide (supprime les incidents enregistrés)
	$(AEGIS) init --reset

train: ## Entraîner le modèle et régénérer docs/BENCHMARK.md (~6 min)
	$(AEGIS) train --duration 600 --captures 6

bench: ## Réévaluer le modèle sauvegardé
	$(AEGIS) bench --duration 600

pdf: ## Régénérer les schémas et compiler les deux PDF (nécessite tectonic)
	./scripts/build_pdf.sh

schemas: ## Régénérer les schémas SVG et vérifier qu'aucun texte ne déborde
	cd docs/schemas && ../../backend/.venv/bin/python tout.py

build: ## Compiler l'interface web dans frontend/dist
	cd frontend && npm run build

serve: ## Lancer l'API (sert aussi l'interface compilée sur http://127.0.0.1:8000)
	$(AEGIS) serve

demo: ## Lancer l'API avec le réseau de laboratoire déjà démarré
	cd backend && AEGIS_AUTOSTART=lab AEGIS_AUTOSTART_SPEED=6 PYTHONPATH=. \
	  .venv/bin/python -m aegis.cli serve

dev: ## Serveur de développement du frontend (port 5173, proxy vers l'API)
	cd frontend && npm run dev

test: ## Suite de tests complète
	cd backend && .venv/bin/python -m pytest -q

test-fast: ## Tests rapides (sans ceux qui entraînent un modèle)
	cd backend && .venv/bin/python -m pytest -q tests/test_core.py tests/test_api.py

lint: ## Vérification de types du frontend
	cd frontend && npx tsc --noEmit

clean: ## Supprimer les artefacts de build
	rm -rf frontend/dist frontend/node_modules/.vite
	find backend -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
