"""La décision d'alerter : pourquoi deux étages valent mieux qu'un."""
from commun import boite_centree, ecrire, entete, fleche, palettes, texte

PALETTES = palettes("cascade.svg", "cascade-dark.svg")

L, H = 900, 470


def losange(cx, cy, w, h, lignes, p):
    pts = f"{cx},{cy - h / 2} {cx + w / 2},{cy} {cx},{cy + h / 2} {cx - w / 2},{cy}"
    s = [f'<polygon points="{pts}" fill="{p["pastille"]}" stroke="{p["accent"]}" '
         f'stroke-width="1.4"/>']
    depart = cy - (len(lignes) - 1) * 8 + 4
    for i, ligne in enumerate(lignes):
        s.append(texte(cx, depart + i * 16, ligne, 11, "titre", ancre="middle", p=p))
    return "".join(s)


def construire(nom, p):
    s = entete(L, H, "La cascade : quand l'étage B peut opposer son veto", p,
               marqueurs=(("arrow", "discret"), ("arrowV", "vert"), ("arrowR", "rouge")))

    s.append(boite_centree(34, 196, 150, 44, [("Flux évalué", True)], p))
    s.append(fleche("M 188 218 L 226 218", p))

    # --- Question 1 : au-dessus du seuil de l'hôte ? -------------------------
    s.append(losange(316, 218, 180, 92,
                     ["score ≥ seuil", "de cet hôte ?"], p))
    s.append(texte(316, 294, "non", 11, "discret", ancre="middle", p=p))
    s.append(fleche("M 316 266 L 316 334", p))
    s.append(boite_centree(214, 338, 204, 48,
                           [("Pas d'alerte", True),
                            ("le score alimente la référence", False)], p,
                           fond="vert_fond", bord="vert_bord", couleur_titre="vert"))

    s.append(texte(420, 206, "oui", 11, "discret", ancre="middle", p=p))
    s.append(fleche("M 408 218 L 452 218", p))

    # --- Question 2 : anomalie forte ? --------------------------------------
    s.append(losange(548, 218, 184, 92, ["score ≥ 0,9975 ?"], p))
    s.append(texte(548, 142, "oui", 11, "discret", ancre="middle", p=p))
    s.append(fleche("M 548 172 L 548 124", p, couleur="rouge", marqueur="arrowR"))
    s.append(boite_centree(430, 62, 240, 58,
                           [("ALERTE", True),
                            ("une anomalie forte alerte toujours,", False),
                            ("même sur une attaque inconnue", False)], p,
                           fond="rouge_fond", bord="rouge_bord", couleur_titre="rouge"))

    s.append(texte(652, 206, "non", 11, "discret", ancre="middle", p=p))
    s.append(fleche("M 640 218 L 684 218", p))

    # --- Question 3 : l'étage B reconnaît-il du trafic normal ? --------------
    s.append(losange(786, 218, 196, 104,
                     ["étage B dit BÉNIN", "avec ≥ 90 % de", "confiance ?"], p))

    s.append(texte(786, 294, "oui", 11, "discret", ancre="middle", p=p))
    s.append(fleche("M 786 272 L 786 334", p, couleur="vert", marqueur="arrowV"))
    s.append(boite_centree(668, 338, 232, 48,
                           [("Alerte supprimée", True),
                            ("341 faux positifs/heure ramenés à 53", False)], p,
                           fond="vert_fond", bord="vert_bord", couleur_titre="vert"))

    s.append(texte(762, 148, "non", 11, "discret", ancre="middle", p=p))
    s.append(fleche("M 786 166 L 786 112 L 678 112", p, couleur="rouge", marqueur="arrowR"))

    # --- Légende -------------------------------------------------------------
    s.append(texte(18, 418, "L'étage A est réglé pour la sensibilité, ce qui coûte des faux "
                            "positifs dans la bande juste au-dessus du seuil. Quand le", 11,
                   "discret", p=p))
    s.append(texte(18, 436, "classifieur supervisé reconnaît ce trafic comme normal — et le dit "
                            "avec assurance — l'alerte est supprimée. Jamais au-delà de", 11,
                   "discret", p=p))
    s.append(texte(18, 454, "0,9975 : c'est cette borne qui préserve la détection des attaques "
                            "que le classifieur n'a jamais apprises.", 11, "discret", p=p))

    s.append("</svg>")
    return "".join(s)


if __name__ == "__main__":
    for nom, palette in PALETTES.items():
        ecrire(nom, construire(nom, palette))
