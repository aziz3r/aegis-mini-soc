"""La clé de regroupement suit la forme de l'attaque."""
from commun import boite_centree, ecrire, entete, fleche, palettes, panneau, texte

PALETTES = palettes("correlation.svg", "correlation-dark.svg")

L, H = 900, 430


def point(cx, cy, r, p, couleur="discret"):
    return f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{p[couleur]}"/>'


def construire(nom, p):
    s = entete(L, H, "Corrélation : la clé de regroupement suit la forme de l'attaque", p)

    formes = [
        ("Un vers plusieurs", "balayage de ports ou de réseau",
         "regroupé sur la source", "one_many"),
        ("Plusieurs vers un", "inondation, slowloris",
         "regroupé sur la victime", "many_one"),
        ("Un vers un", "force brute, balise, exfiltration",
         "regroupé sur la paire", "one_one"),
    ]

    for i, (titre, exemple, cle, genre) in enumerate(formes):
        x = 18 + i * 294
        s.append(panneau(x, 34, 274, 258, p))
        s.append(texte(x + 137, 62, titre, 13, "accent", gras=True, ancre="middle", p=p))
        s.append(texte(x + 137, 80, exemple, 10.5, "discret", ancre="middle", p=p))

        cx, cy = x + 137, 164
        if genre == "one_many":
            s.append(point(cx - 86, cy, 9, p, "accent"))
            for j in range(5):
                yy = cy - 56 + j * 28
                s.append(point(cx + 70, yy, 5, p))
                s.append(fleche(f"M {cx - 74} {cy} L {cx + 56} {yy}", p))
        elif genre == "many_one":
            for j in range(5):
                yy = cy - 56 + j * 28
                s.append(point(cx - 70, yy, 5, p))
                s.append(fleche(f"M {cx - 58} {yy} L {cx + 72} {cy}", p))
            s.append(point(cx + 86, cy, 9, p, "accent"))
        else:
            s.append(point(cx - 74, cy, 9, p, "accent"))
            s.append(point(cx + 74, cy, 9, p, "accent"))
            s.append(fleche(f"M {cx - 60} {cy} L {cx + 58} {cy}", p))

        s.append(boite_centree(x + 20, 240, 234, 34, [(cle, True)], p,
                               fond="pastille", bord="accent", couleur_titre="accent"))

    # --- Résultat ------------------------------------------------------------
    s.append(fleche("M 450 300 L 450 326", p))
    s.append(boite_centree(298, 330, 304, 50,
                           [("8 994 alertes deviennent 1 incident", True),
                            ("mesuré en direct sur un balayage de ports", False)], p,
                           fond="pastille", bord="accent", couleur_titre="accent"))

    s.append(texte(18, 412, "Une inondation produit des milliers d'alertes par minute. Les "
                            "afficher une par une est la manière dont un SOC se noie.", 11,
                   "discret", p=p))

    s.append("</svg>")
    return "".join(s)


if __name__ == "__main__":
    for nom, palette in PALETTES.items():
        ecrire(nom, construire(nom, palette))
