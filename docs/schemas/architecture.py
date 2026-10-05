"""Génère les deux schémas de la chaîne de détection, clair et sombre."""
from commun import boite, boite_centree, ecrire, entete, fleche, palettes, panneau, texte

PALETTES = palettes("architecture.svg", "architecture-dark.svg")

L, H = 940, 600


def construire(nom, p):
    s = entete(L, H, "Chaîne de détection AEGIS : des paquets aux incidents", p,
               marqueurs=(("arrow", "discret"), ("arrowA", "accent")))

    # --- Sources -------------------------------------------------------------
    s.append(panneau(18, 96, 178, 212, p))
    s.append(texte(107, 124, "Sources de trafic", 13, "accent", gras=True, ancre="middle", p=p))
    for i, (titre, sous) in enumerate([
            ("Laboratoire", "vérité terrain connue"),
            ("Rejeu de PCAP", "99 000 paquets/s"),
            ("Capture réelle", "scapy, root requis")]):
        y = 140 + i * 56
        s.append(boite(32, y, 150, titre, p, taille=11.5, gras=True, couleur="titre"))
        s.append(texte(107, y + 38, sous, 10, "discret", ancre="middle", p=p))

    s.append(fleche("M 200 202 L 242 202", p, couleur="accent", marqueur="arrowA"))

    # --- Moteur --------------------------------------------------------------
    s.append(panneau(246, 34, 300, 420, p))
    s.append(texte(396, 60, "Moteur de détection", 13.5, "accent", gras=True,
                   ancre="middle", p=p))

    etapes = [
        ("Assemblage en flux", "5-uplet bidirectionnel · tas d'échéances"),
        ("52 features", "33 flux · 15 hôte source · 4 hôte cible"),
        ("Étage A — IsolationForest", "trafic bénin seul · score calibré FRE"),
        ("Seuil adaptatif", "quantile par hôte, sur un plancher global"),
        ("Étage B — HistGradientBoosting", "nomme la famille et oppose un veto"),
        ("Attribution par occlusion", "pourquoi cette alerte"),
    ]
    for i, (titre, sous) in enumerate(etapes):
        y = 76 + i * 62
        s.append(boite_centree(262, y, 268, 48,
                               [(titre, True), (sous, False)], p, taille=11.5))
        if i < len(etapes) - 1:
            s.append(fleche(f"M 396 {y + 48} L 396 {y + 62}", p))

    s.append(fleche("M 550 234 L 592 234", p, couleur="accent", marqueur="arrowA"))

    # --- Couche SOC ----------------------------------------------------------
    s.append(panneau(596, 96, 326, 212, p))
    s.append(texte(759, 124, "Couche SOC", 13.5, "accent", gras=True, ancre="middle", p=p))
    s.append(boite_centree(612, 140, 294, 50,
                           [("Corrélation en incidents", True),
                            ("regroupées selon la forme de l'attaque", False)], p))
    s.append(boite_centree(612, 200, 294, 50,
                           [("MITRE ATT&CK · criticité des actifs", True),
                            ("gravité = marge x valeur de l'actif", False)], p))
    s.append(boite_centree(612, 260, 294, 34,
                           [("SQLite (WAL) ou PostgreSQL", True)], p))

    s.append(fleche("M 759 312 L 759 344", p))

    # --- API et interface ----------------------------------------------------
    s.append(boite_centree(612, 348, 294, 50,
                           [("API FastAPI", True),
                            ("REST + WebSocket · JWT · 3 rôles · audit", False)], p))
    s.append(fleche("M 759 402 L 759 428", p))
    s.append(boite_centree(612, 432, 294, 50,
                           [("Interface React + TypeScript", True),
                            ("8 écrans · temps réel", False)], p))

    # --- Légende -------------------------------------------------------------
    s.append(texte(18, 522, "Les trois sources traversent exactement la même chaîne : rien du "
                            "chemin de détection n'est simulé. L'horloge est celle des", 11,
                   "discret", p=p))
    s.append(texte(18, 540, "paquets, jamais celle du mur — c'est ce qui garantit qu'un PCAP "
                            "rejoué à x60 produit les mêmes flux que la capture d'origine.", 11,
                   "discret", p=p))
    s.append(texte(18, 566, "L'étage A n'a jamais vu d'attaque : il peut donc en signaler une "
                            "qu'il ne connaît pas. L'étage B ne décide pas s'il faut alerter,", 11,
                   "discret", p=p))
    s.append(texte(18, 584, "il nomme ce que l'anomalie ressemble — et supprime les fausses "
                            "alertes qu'il reconnaît comme du trafic normal.", 11,
                   "discret", p=p))

    s.append("</svg>")
    return "".join(s)


if __name__ == "__main__":
    for nom, palette in PALETTES.items():
        ecrire(nom, construire(nom, palette))
