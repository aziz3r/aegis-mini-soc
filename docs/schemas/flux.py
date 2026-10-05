"""Le cycle de vie d'un flux : de l'assemblage à l'export."""
from commun import boite_centree, ecrire, entete, fleche, palettes, panneau, texte

PALETTES = palettes("cycle-de-vie.svg", "cycle-de-vie-dark.svg")

L, H = 900, 400


def construire(nom, p):
    s = entete(L, H, "Cycle de vie d'un flux : les quatre façons d'être exporté", p,
               marqueurs=(("arrow", "discret"), ("arrowA", "accent")))

    s.append(boite_centree(34, 150, 158, 54,
                           [("Premier paquet", True), ("le flux est ouvert", False)], p,
                           fond="pastille", bord="accent", couleur_titre="accent"))
    s.append(fleche("M 196 177 L 236 177", p, couleur="accent", marqueur="arrowA"))

    s.append(panneau(240, 60, 230, 234, p))
    s.append(texte(355, 88, "Flux actif", 13, "accent", gras=True, ancre="middle", p=p))
    s.append(texte(355, 110, "les paquets s'accumulent", 10.5, "discret",
                   ancre="middle", p=p))
    for i, ligne in enumerate(["compteurs par sens", "tailles et intervalles",
                               "drapeaux TCP", "entropie de charge utile"]):
        s.append(texte(260, 140 + i * 24, "·  " + ligne, 11, "texte", p=p))
    s.append(texte(355, 258, "l'horloge est celle des paquets", 10.5, "discret",
                   ancre="middle", p=p))
    s.append(texte(355, 276, "jamais celle du mur", 10.5, "discret",
                   ancre="middle", p=p))

    sorties = [
        ("Fin de connexion", "RST, ou FIN des deux côtés", "immédiat"),
        ("SYN sans réponse", "rien d'autre n'arrivera jamais", "3 s"),
        ("Inactivité", "plus aucun paquet", "15 s"),
        ("Flux trop long", "exporté par tranches", "120 s"),
    ]
    for i, (titre, sous, delai) in enumerate(sorties):
        y = 46 + i * 70
        s.append(fleche(f"M 474 177 C 510 177, 516 {y + 26}, 552 {y + 26}", p))
        s.append(boite_centree(556, y, 326, 52,
                               [(f"{titre}  —  {delai}", True), (sous, False)], p))

    s.append(texte(18, 338, "L'export après 3 s d'une tentative de connexion sans réponse "
                            "n'est pas un détail : un SYN resté sans réponse est déjà une", 11,
                   "discret", p=p))
    s.append(texte(18, 356, "observation complète. Attendre le délai d'inactivité complet "
                            "ajoutait 15 secondes à la détection de chaque balayage et de", 11,
                   "discret", p=p))
    s.append(texte(18, 374, "chaque inondation — les deux attaques composées presque "
                            "entièrement de SYN sans réponse. Latence médiane : de 16 s à 3 s.", 11,
                   "discret", p=p))

    s.append("</svg>")
    return "".join(s)


if __name__ == "__main__":
    for nom, palette in PALETTES.items():
        ecrire(nom, construire(nom, palette))
