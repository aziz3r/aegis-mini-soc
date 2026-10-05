"""Vérifie qu'aucun texte ne déborde de son schéma.

Un débordement ne casse rien : il passe inaperçu dans le code et se voit
seulement à l'œil, sur le rendu. Ce contrôle estime la largeur de chaque
<text> à partir des chasses d'Helvetica — assez proche de la police système
pour attraper un vrai débordement — et refuse qu'un texte sorte de la toile.
"""
import pathlib
import sys
import xml.etree.ElementTree as ET

MARGE = 12           # marge minimale attendue au bord de la toile
ELARGISSEMENT = 1.05  # la police système rend un peu plus large qu'Helvetica
GRAS = 1.06

CHASSES = {" ": 278, "!": 278, '"': 355, "#": 556, "$": 556, "%": 889, "&": 667,
           "'": 191, "(": 333, ")": 333, "*": 389, "+": 584, ",": 278, "-": 333,
           ".": 278, "/": 278, ":": 278, ";": 278, "<": 584, "=": 584, ">": 584,
           "?": 556, "@": 1015, "[": 278, "\\": 278, "]": 278, "^": 469, "_": 556,
           "`": 333, "{": 334, "|": 260, "}": 334, "~": 584}
CHASSES.update({c: 556 for c in "0123456789"})
CHASSES.update({c: 556 for c in "abcdeghknopqsuvxyzâàäéèêëôöûùüç"})
CHASSES.update({c: 222 for c in "ilïî"})
CHASSES.update({c: 278 for c in "jft"})
CHASSES.update({c: 333 for c in "r"})
CHASSES.update({c: 500 for c in "w"})
CHASSES.update({c: 889 for c in "m"})
CHASSES.update({c: 1000 for c in "œæ"})
CHASSES.update({c: 667 for c in "ABCDEGHKNOPQRSUVXYZÀÂÄÉÈÊËÎÏÔÖÛÙÜÇ"})
CHASSES.update({c: 278 for c in "I"})
CHASSES.update({c: 611 for c in "FTL"})
CHASSES.update({c: 944 for c in "MW"})
CHASSES.update({"—": 1000, "–": 556, "·": 278, "→": 1000, "«": 556, "»": 556,
                "’": 191, "≥": 584, "≤": 584, "×": 584})


def largeur(contenu, taille, gras):
    total = sum(CHASSES.get(c, 556) for c in contenu)
    return total / 1000 * taille * (GRAS if gras else 1) * ELARGISSEMENT


def controler(chemin):
    arbre = ET.parse(chemin)
    racine = arbre.getroot()
    toile = float(racine.get("width"))
    anomalies = []
    for noeud in racine.iter("{http://www.w3.org/2000/svg}text"):
        contenu = "".join(noeud.itertext())
        if not contenu.strip():
            continue
        taille = float(noeud.get("font-size", 11.5))
        gras = noeud.get("font-weight") == "600"
        w = largeur(contenu, taille, gras)
        x = float(noeud.get("x"))
        ancre = noeud.get("text-anchor", "start")
        gauche = x - w / 2 if ancre == "middle" else (x - w if ancre == "end" else x)
        droite = gauche + w
        if gauche < MARGE or droite > toile - MARGE:
            anomalies.append((contenu[:58], round(gauche), round(droite), round(toile)))
    return anomalies


def principal():
    docs = pathlib.Path(__file__).resolve().parent.parent
    total = 0
    for fichier in sorted(docs.glob("*.svg")):
        anomalies = controler(fichier)
        if anomalies:
            total += len(anomalies)
            print(f"  ✘ {fichier.name}")
            for contenu, g, d, t in anomalies:
                print(f"      « {contenu} »  → {g}..{d} hors de 0..{t}")
        else:
            print(f"  ✔ {fichier.name}")
    if total:
        print(f"\n{total} texte(s) débordent.")
        return 1
    print("\nAucun débordement.")
    return 0


if __name__ == "__main__":
    sys.exit(principal())
