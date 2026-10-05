"""Pourquoi la règle « médiane + k·MAD » a détruit le rappel."""
from commun import boite_centree, ecrire, entete, fleche, palettes, panneau, texte

PALETTES = palettes("seuil.svg", "seuil-dark.svg")

L, H = 900, 430


def construire(nom, p):
    s = entete(L, H, "Le seuil adaptatif : pourquoi un quantile et pas un MAD", p,
               marqueurs=(("arrow", "discret"), ("arrowV", "vert"), ("arrowR", "rouge")))

    # --- Le constat de départ ------------------------------------------------
    s.append(boite_centree(282, 30, 336, 54,
                           [("Le score de l'étage A est un percentile", True),
                            ("du trafic bénin : donc quasi uniforme sur [0, 1]", False)], p,
                           fond="pastille", bord="accent", couleur_titre="accent"))
    s.append(texte(450, 102, "médiane ≈ 0,52   ·   MAD ≈ 0,24", 11.5, "discret",
                   ancre="middle", p=p, mono=True))

    s.append(fleche("M 330 116 L 250 148", p, couleur="rouge", marqueur="arrowR"))
    s.append(fleche("M 570 116 L 650 148", p, couleur="vert", marqueur="arrowV"))

    # --- La mauvaise piste ---------------------------------------------------
    s.append(panneau(18, 152, 414, 196, p, fond="rouge_fond", bord="rouge_bord"))
    s.append(texte(225, 180, "La règle classique", 13, "rouge", gras=True,
                   ancre="middle", p=p))
    s.append(texte(225, 212, "médiane + 4 × 1,4826 × MAD ≈ 1,94", 12, "titre",
                   ancre="middle", p=p, mono=True))
    s.append(texte(225, 242, "plafonné pour TOUS les hôtes", 11.5, "rouge",
                   gras=True, ancre="middle", p=p))
    s.append(boite_centree(70, 262, 310, 40, [("rappel tombé à 14 %", True)], p,
                           fond="boite", bord="rouge_bord", couleur_titre="rouge"))
    s.append(texte(225, 326, "Le MAD suppose un cœur serré et de rares valeurs extrêmes.",
                   10.5, "discret", ancre="middle", p=p))

    # --- La bonne piste ------------------------------------------------------
    s.append(panneau(468, 152, 414, 196, p, fond="vert_fond", bord="vert_bord"))
    s.append(texte(675, 180, "La statistique adaptée", 13, "vert", gras=True,
                   ancre="middle", p=p))
    s.append(texte(675, 212, "max(plancher, quantile(scores, 0,99))", 11.5, "titre",
                   ancre="middle", p=p, mono=True))
    s.append(texte(675, 242, "se lit comme un budget de faux positifs", 11.5, "vert",
                   gras=True, ancre="middle", p=p))
    s.append(boite_centree(520, 262, 310, 40, [("rappel 99,6 %", True)], p,
                           fond="boite", bord="vert_bord", couleur_titre="vert"))
    s.append(texte(675, 326, "Une loi uniforme n'a ni cœur serré ni valeurs extrêmes rares.",
                   10.5, "discret", ancre="middle", p=p))

    # --- Garde-fou -----------------------------------------------------------
    s.append(texte(18, 380, "Garde-fou : seuls les scores qui n'ont PAS alerté alimentent la "
                            "référence. Sans cela, un hôte sous attaque prolongée", 11,
                   "discret", p=p))
    s.append(texte(18, 398, "normaliserait son propre trafic d'attaque et se tairait — c'est "
                            "ainsi qu'un attaquant patient bat une adaptation naïve.", 11,
                   "discret", p=p))
    s.append(texte(18, 416, "Un plafond limite aussi jusqu'où un hôte peut relever sa barre.",
                   11, "discret", p=p))

    s.append("</svg>")
    return "".join(s)


if __name__ == "__main__":
    for nom, palette in PALETTES.items():
        ecrire(nom, construire(nom, palette))
