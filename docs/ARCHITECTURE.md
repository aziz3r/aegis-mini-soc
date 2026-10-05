# Architecture

Ce document explique **pourquoi** le système est fait ainsi. Le quoi est dans le
code ; les choix qui ne se lisent pas dans le code sont ici.

---

## Vue d'ensemble

```
┌─ source ──────────────┐
│ laboratoire · PCAP ·  │  horloge = celle des paquets, jamais celle du mur
│ capture d'interface   │
└───────────┬───────────┘
            │ lots de paquets normalisés
┌───────────▼───────────┐
│ FlowTable             │  5-uplet bidirectionnel, expiration par tas paresseux
│ + HostTracker         │  fenêtres 10 s / 60 s à agrégats incrémentaux
│ + PeerTracker         │  fenêtre côté destination
└───────────┬───────────┘
            │ flux + 52 features
┌───────────▼───────────┐
│ Engine                │  étage A → score calibré
│                       │  seuil adaptatif de l'hôte (lu AVANT apprentissage)
│                       │  étage B → famille, et veto des faux positifs
│                       │  attribution par occlusion (budgétée)
└───────────┬───────────┘
            │ verdicts
┌───────────▼───────────┐
│ Correlator            │  regroupement selon la forme de l'attaque
│                       │  gravité = marge × criticité × confiance
└───────────┬───────────┘
            │ événements d'incident
┌───────────▼───────────┐
│ Writer (par lots)     │  upsert des incidents, ajout des alertes (plafonné),
│                       │  agrégats par seconde, profils d'hôtes
└───────────┬───────────┘
            ├──────────► SQLite / PostgreSQL ──► API REST ──► interface web
            └──────────► Bus ──────────────────► WebSocket ─► flux temps réel
```

---

## Décisions et leurs raisons

### Un seul processus, une seule tâche d'écriture

Le moteur, le corrélateur et l'écrivain vivent dans la même tâche asyncio.
Conséquence : aucun verrou, aucune course. SQLite en mode WAL permet à l'API de
lire pendant que cette tâche écrit. Les écritures, qui sont bloquantes, sont
déportées dans un fil d'exécution — les laisser sur la boucle d'événements
gèlerait l'API le temps de chaque commit.

Le bus de publication est volontairement **in-process** et non Redis : un
déploiement mono-processus n'a pas besoin d'un courtier, et en introduire un
ajouterait une dépendance d'exploitation sans aucun gain de comportement.
L'interface est étroite (`publish` / `subscribe`) précisément pour qu'un
adaptateur Redis Streams ou Kafka puisse la remplacer sans toucher au reste.

### Un abonné lent ne doit jamais ralentir l'ingestion

Chaque abonné au bus possède une file bornée et perd ses événements les plus
anciens quand il ne suit pas. Perdre des images pour un onglet de navigateur vaut
toujours mieux que bloquer la capture pour tout le monde. Même principe côté
capture : le fil scapy ne bloque jamais, il compte les paquets perdus et
l'interface les affiche.

### L'expiration des flux par tas paresseux

La version initiale parcourait tous les flux actifs à chaque paquet : O(n) par
paquet, et l'effondrement survenait exactement quand il ne fallait pas — pendant
une inondation ou un slowloris, dont le principe même est d'ouvrir des milliers
de connexions simultanées. Mesuré : **12 000 → 33 000 paquets/s**.

Chaque paquet empile désormais une échéance ; les entrées périmées (le flux a reçu
un paquet depuis, ou a déjà été exporté) sont reconnues au dépilage grâce à un
compteur de génération par flux. L'équivalence avec le parcours naïf est
**vérifiée par un test** sur 240 s de trafic mixte, pas supposée.

### Les agrégats de fenêtre sont incrémentaux

Même raison. Recalculer une fenêtre de 60 s par flux exporté est O(n·w), et pendant
une inondation un hôte détient des milliers d'enregistrements dans sa fenêtre.
Tout est maintenu en O(1) amorti, les cardinalités (« destinations distinctes »)
étant des multi-ensembles dont le cardinal est un `len()`.

### Le générateur de trafic est chunké

Il planifie toutes les sessions d'une période à l'avance. Demander une période de
24 h revenait donc à construire près d'un demi-million de générateurs avant
d'émettre le premier paquet : le démarrage de l'API se bloquait. Le trafic est
désormais construit par tranches de 600 s. Le coût est qu'une session encore
ouverte à une frontière de tranche y est coupée — d'où une tranche très supérieure
à la durée d'une session ordinaire.

### Le seuil est lu avant d'être appris

Dans `Engine.score_flows`, le seuil de l'hôte est interrogé **avant** que le score
du flux courant n'entre dans la référence. Sans cette précaution, un flux
influencerait le seuil contre lequel il est lui-même jugé. C'est subtil, c'est
invisible dans les métriques globales, et c'est testé.

### Le budget d'explication

L'attribution par occlusion coûte un appel de scoring vectorisé par alerte
expliquée. Une inondation peut lever des centaines d'alertes par seconde, et les
expliquer toutes dominerait la boucle sans aucun bénéfice : elles sont fusionnées
en un seul incident, qui n'a besoin que d'une explication. Le budget plafonne le
travail par lot, et l'incident conserve l'explication de son alerte la plus forte.

### Le plafond d'alertes par incident

Conserver la dix-millième requête SYN identique d'une inondation n'a aucune valeur
d'investigation et ferait croître la base sans limite. Les alertes sont ajoutées
jusqu'à un plafond ; le compteur d'occurrences, lui, continue de raconter toute
l'histoire.

### Le port de destination n'est pas une feature

Un modèle à arbres mémoriserait les ports du laboratoire (22, 80, 53…) et
produirait d'excellents scores, sans aucun rapport avec sa capacité à généraliser.
Seules les propriétés structurelles du port sont conservées.

### L'index du front, lui, n'est jamais mis en cache

Le build donne à chaque ressource un nom contenant son empreinte : elles peuvent
donc être mises en cache indéfiniment. `index.html` est le seul fichier dont le
nom ne change jamais ; une copie en cache épinglerait le navigateur sur les noms
de ressources du build précédent, et l'application continuerait silencieusement
d'exécuter l'ancien code après un déploiement.

---

## Chemin de données, en détail

### De l'octet au flux

Les trois sources produisent un `Packet` normalisé. `Packet.ts` porte toujours
l'horloge de **capture**, parce que les délais d'expiration s'expriment en temps
de capture : un PCAP rejoué à ×60 doit produire les mêmes flux que l'original.
L'heure d'arrivée réelle est enregistrée séparément pour l'affichage.

### Du flux au score

`vectorize` sérialise les features dans l'ordre de `FEATURE_NAMES`, unique source
de vérité. Le modèle enregistre cette liste et **refuse de se charger** si elle a
changé : une colonne qui se décale silencieusement est le pire mode de panne d'un
système de ce genre.

### Du score à l'alerte

```python
seuil      = seuils.threshold(hôte)          # lu avant apprentissage
alerte     = score >= seuil
si alerte et famille == BENIGN et confiance >= 0.90 et score < 0.9975 :
    alerte = False                           # veto de l'étage B
seuils.observe(hôte, score, alerte)          # les alertes n'alimentent pas la référence
```

### De l'alerte à l'incident

Clé de regroupement selon la forme de l'attaque, fenêtre glissante de 60 s,
priorité sur 100 combinant la marge au-dessus du seuil, la criticité de l'actif,
la confiance du classifieur et un appoint de volume.

---

## Extension

| Besoin | Point d'entrée |
|---|---|
| Nouvelle source | hériter de `Source`, implémenter `batches()` |
| Nouvelle feature | ajouter à `FLOW_FEATURES`/`HOST_FEATURES`, puis `aegis train` |
| Nouvelle famille | `sources/lab.py` + `core/mitre.py` |
| Autre modèle | respecter `score()` / `classify()` / `explain()` |
| PostgreSQL | `AEGIS_DATABASE_URL` ; rien dans le schéma n'est propre à SQLite |
| Bus externe | remplacer `api/bus.py` derrière `publish` / `subscribe` |

---

## Ce qui reste à faire

1. **Rejeu validé sur PCAP public** (CIC-IDS2017) avec ses étiquettes officielles :
   c'est ce qui permettrait de comparer ces chiffres à la littérature.
2. **Ré-entraînement sur les verdicts d'analystes.** Les jugements sont déjà
   enregistrés et exploitables ; la boucle n'est pas câblée.
3. **Suivi de dérive** entre la distribution d'entraînement et le trafic du jour.
4. **Réponse automatique** (blocage nftables/pfctl) en mode simulation par défaut.
5. **Plusieurs sondes** alimentant un corrélateur central.
