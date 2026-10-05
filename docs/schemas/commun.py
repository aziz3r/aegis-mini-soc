"""Briques communes aux schémas de docs/.

Chaque schéma est décrit une seule fois ; la version claire et la version sombre
en sont dérivées. C'est ce qui empêche les deux variantes de diverger, et c'est
aussi ce qui permet de corriger un chiffre à un seul endroit.
"""
import pathlib

POLICE = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Inter, Roboto, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, monospace"

CLAIR = dict(fond="#ffffff", panneau="#f7f8fa", boite="#ffffff", bord="#d8dce2",
             titre="#15171c", texte="#4b5563", discret="#8b9098", accent="#0e7490",
             pastille="#e0f2fe", vert="#0a7a3d", vert_fond="#eef7f1", vert_bord="#a8d5bc",
             alerte="#b45309", alerte_fond="#fef6e7", alerte_bord="#e8c98a",
             rouge="#c0392b", rouge_fond="#fdecea", rouge_bord="#f0b4ae")

SOMBRE = dict(fond="#0d1117", panneau="#161b22", boite="#11161d", bord="#30363d",
              titre="#e6edf3", texte="#9aa4b1", discret="#7d8590", accent="#22d3ee",
              pastille="#0b2b33", vert="#3fb950", vert_fond="#122118", vert_bord="#2d5a3d",
              alerte="#e3a008", alerte_fond="#2b2213", alerte_bord="#5c4a1f",
              rouge="#f85149", rouge_fond="#2a1416", rouge_bord="#6e2b28")


def palettes(nom_clair, nom_sombre):
    """Associe chaque fichier de sortie à sa palette."""
    return {nom_clair: CLAIR, nom_sombre: SOMBRE}


def echappe(contenu):
    return (contenu.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def texte(x, y, contenu, taille=11.5, couleur="texte", gras=False, ancre="start",
          p=None, mono=False):
    g = ' font-weight="600"' if gras else ""
    a = f' text-anchor="{ancre}"' if ancre != "start" else ""
    famille = MONO if mono else POLICE
    return (f'<text x="{x}" y="{y}" font-family="{famille}" font-size="{taille}"'
            f'{g} fill="{p[couleur]}"{a}>{echappe(contenu)}</text>')


def boite(x, y, w, contenu, p, taille=11.5, h=24, couleur="texte", fond="boite",
          bord="bord", gras=False, mono=False):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{p[fond]}" '
            f'stroke="{p[bord]}" stroke-width="1"/>'
            + texte(x + 10, y + h / 2 + 4, contenu, taille, couleur, gras=gras, p=p,
                    mono=mono))


def boite_centree(x, y, w, h, lignes, p, taille=11.5, fond="boite", bord="bord",
                  couleur_titre="titre"):
    """Une boîte dont le texte est centré, une ligne de titre puis des sous-lignes."""
    s = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{p[fond]}" '
         f'stroke="{p[bord]}" stroke-width="1.4"/>']
    cx = x + w / 2
    depart = y + h / 2 - (len(lignes) - 1) * 8 + 4
    for i, (contenu, gras) in enumerate(lignes):
        s.append(texte(cx, depart + i * 16, contenu, taille if i == 0 else taille - 1,
                       couleur_titre if gras else "discret", gras=gras, ancre="middle", p=p))
    return "".join(s)


def panneau(x, y, w, h, p, fond="panneau", bord="bord"):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{p[fond]}" '
            f'stroke="{p[bord]}" stroke-width="1.5"/>')


def fleche(d, p, pointille=False, couleur="discret", marqueur="arrow"):
    tirets = ' stroke-dasharray="5 4"' if pointille else ""
    return (f'<path d="{d}" fill="none" stroke="{p[couleur]}" stroke-width="1.6"'
            f'{tirets} marker-end="url(#{marqueur})"/>')


def marqueur(identifiant, couleur, p):
    return (f'<marker id="{identifiant}" viewBox="0 0 10 10" refX="9" refY="5" '
            f'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
            f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{p[couleur]}"/></marker>')


def entete(largeur, hauteur, titre_accessible, p, marqueurs=(("arrow", "discret"),)):
    defs = "".join(marqueur(i, c, p) for i, c in marqueurs)
    return [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {largeur} {hauteur}" '
            f'width="{largeur}" height="{hauteur}" role="img" '
            f'aria-label="{echappe(titre_accessible)}">',
            f'<defs>{defs}</defs>',
            f'<rect width="{largeur}" height="{hauteur}" rx="12" fill="{p["fond"]}"/>']


def ecrire(nom, contenu):
    """Écrit dans docs/, quel que soit le répertoire courant."""
    (pathlib.Path(__file__).resolve().parent.parent / nom).write_text(contenu,
                                                                     encoding="utf-8")
    print(f"  ✔ {nom}")
