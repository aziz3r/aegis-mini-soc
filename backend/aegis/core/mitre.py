"""Attack families mapped to MITRE ATT&CK, with analyst guidance.

An alert that says "score 0.93" tells an analyst nothing actionable. An alert
that says "Network Service Discovery (T1046), check whether the source is an
authorised scanner, then block at the edge" can be worked.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FamilyInfo:
    key: str
    title: str
    technique: str
    tactic: str
    description: str
    triage: str
    default_criticality: int  # 1..5, drives severity when the asset is unknown


FAMILIES: dict[str, FamilyInfo] = {
    "PORT_SCAN": FamilyInfo(
        "PORT_SCAN", "Balayage de ports", "T1046", "Discovery",
        "Une source teste un grand nombre de ports sur une même machine sans "
        "établir de connexion complète — signature d'une reconnaissance SYN.",
        "Vérifier si la source est un scanner autorisé (inventaire, Nessus). "
        "Sinon, bloquer la source au pare-feu et chercher ce qu'elle a trouvé d'ouvert.",
        3),
    "NET_SCAN": FamilyInfo(
        "NET_SCAN", "Balayage réseau", "T1018", "Discovery",
        "Une source énumère les machines du sous-réseau sur quelques ports "
        "sensibles (445, 22, 3389) : cartographie avant déplacement latéral.",
        "Identifier la source. Si elle est interne, la traiter comme potentiellement "
        "compromise : c'est le comportement typique d'un implant qui cherche sa prochaine cible.",
        4),
    "DOS_FLOOD": FamilyInfo(
        "DOS_FLOOD", "Déni de service volumétrique", "T1498", "Impact",
        "Inondation de SYN vers un service, depuis de nombreuses sources, sans "
        "aucune connexion menée à terme. Les adresses sources sont souvent usurpées.",
        "Activer la protection SYN (cookies), limiter le débit en amont. Ne pas "
        "perdre de temps à bloquer les sources une par une : elles sont probablement fausses.",
        5),
    "SSH_BRUTEFORCE": FamilyInfo(
        "SSH_BRUTEFORCE", "Force brute SSH", "T1110.001", "Credential Access",
        "Tentatives d'authentification répétées sur le port 22 : poignée de main "
        "complète puis coupure immédiate, en rafale.",
        "Vérifier dans les journaux auth si une tentative a réussi. Désactiver "
        "l'authentification par mot de passe, mettre en place fail2ban, bloquer la source.",
        4),
    "WEB_BRUTEFORCE": FamilyInfo(
        "WEB_BRUTEFORCE", "Force brute applicative", "T1110.004", "Credential Access",
        "Requêtes POST quasi identiques et très répétitives vers un formulaire "
        "d'authentification : bourrage d'identifiants.",
        "Vérifier les comptes visés et les éventuels succès. Activer la limitation "
        "de débit et un CAPTCHA sur le formulaire, forcer la rotation des mots de passe touchés.",
        4),
    "SLOWLORIS": FamilyInfo(
        "SLOWLORIS", "Déni de service par épuisement", "T1499.003", "Impact",
        "Un grand nombre de connexions maintenues ouvertes avec des en-têtes HTTP "
        "envoyés au compte-gouttes, pour saturer le pool de connexions du serveur.",
        "Réduire les délais d'attente d'en-tête côté serveur, placer un proxy "
        "inverse qui mutualise les connexions, limiter le nombre de sockets par IP.",
        4),
    "DNS_TUNNEL": FamilyInfo(
        "DNS_TUNNEL", "Tunnel DNS", "T1071.004", "Command and Control",
        "Requêtes DNS anormalement volumineuses et à forte entropie, à cadence "
        "régulière : des données sont encodées dans les sous-domaines.",
        "Inspecter les domaines interrogés, bloquer la zone parente, isoler la "
        "machine source : elle exécute déjà du code non autorisé.",
        5),
    "EXFILTRATION": FamilyInfo(
        "EXFILTRATION", "Exfiltration de données", "T1041", "Exfiltration",
        "Volume sortant important et chiffré depuis une machine interne vers une "
        "destination externe sur un port inhabituel. Le ratio montant/descendant est inversé.",
        "Isoler immédiatement la machine source du réseau, préserver les preuves, "
        "identifier les données concernées, bloquer la destination.",
        5),
    "C2_BEACON": FamilyInfo(
        "C2_BEACON", "Balise de commande et contrôle", "T1071.001", "Command and Control",
        "Contacts courts, de taille constante et à intervalle quasi fixe vers une "
        "même destination externe : un implant qui prend ses ordres.",
        "Isoler la machine, bloquer la destination, rechercher la persistance. "
        "La régularité horaire est la signature : un humain n'est jamais aussi ponctuel.",
        5),
    "UNKNOWN": FamilyInfo(
        "UNKNOWN", "Anomalie non classée", "-", "-",
        "Le trafic s'écarte nettement de la normale apprise sur cet hôte, mais ne "
        "correspond à aucune famille connue avec une confiance suffisante.",
        "C'est le cas intéressant : soit un comportement légitime nouveau à "
        "intégrer à la référence, soit une attaque que le classifieur n'a jamais vue. "
        "Examiner les contributions de features pour trancher.",
        3),
    "BENIGN": FamilyInfo(
        "BENIGN", "Trafic normal", "-", "-",
        "Classé comme trafic légitime par le classifieur supervisé, tout en ayant "
        "dépassé le seuil d'anomalie de l'hôte.",
        "Candidat probable à un faux positif : si confirmé, le clore en « faux positif » "
        "pour qu'il alimente le ré-entraînement.",
        2),
}


def info(family: str) -> FamilyInfo:
    return FAMILIES.get(family, FAMILIES["UNKNOWN"])
