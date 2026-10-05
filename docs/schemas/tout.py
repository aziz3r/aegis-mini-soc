"""Régénère tous les schémas, puis vérifie qu'aucun texte ne déborde.

À lancer après toute retouche d'un générateur :

    python3 docs/schemas/tout.py

Chaque schéma est décrit une seule fois ; les variantes claire et sombre en
sont dérivées, ce qui les empêche de diverger.
"""
import pathlib
import runpy
import sys

import verifier

GENERATEURS = ["architecture.py", "flux.py", "cascade.py", "seuil.py", "correlation.py"]

ici = pathlib.Path(__file__).resolve().parent
for generateur in GENERATEURS:
    runpy.run_path(str(ici / generateur), run_name="__main__")

print()
sys.exit(verifier.principal())
