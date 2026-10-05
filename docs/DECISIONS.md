# Journal des décisions

Les bugs et choix de conception qui ont réellement changé le système pendant sa
construction. Ce fichier existe parce que les décisions les plus importantes sont
celles qu'on ne devine pas en lisant le code.

---

## 1. Le seuil adaptatif `médiane + k·MAD` détruisait le rappel

**Symptôme.** Première évaluation complète : rappel **14,33 %**. Le PR-AUC restait
pourtant à 0,993 — le modèle classait donc correctement, mais le point de
fonctionnement était absurde.

**Cause.** Les scores de l'étage A sont la fonction de répartition empirique du
trafic bénin : sur du trafic normal ils sont donc **quasi uniformes** sur [0, 1].
Médiane ≈ 0,52, MAD ≈ 0,24, et `0,52 + 4 × 1,4826 × 0,24 ≈ 1,94` — plafonné au
maximum pour **tous** les hôtes. La règle du MAD suppose une distribution à cœur
serré avec de rares valeurs extrêmes ; une loi uniforme n'a ni l'un ni l'autre.

**Correction.** Un **quantile des scores de l'hôte** (0,99), borné par un plancher
global. Dans un espace de percentiles, c'est la statistique qui a un sens, et elle
se lit directement comme un budget de faux positifs.

**Leçon.** Une statistique robuste n'est robuste que pour la forme de distribution
qu'elle suppose.

---

## 2. L'étage B ne servait qu'à étiqueter — il valait bien mieux

**Symptôme.** Seuil correct, rappel 99,8 %, mais **341 faux positifs/heure** sur du
trafic sans la moindre attaque. Inexploitable pour un analyste.

**Observation.** Le classifieur supervisé reconnaissait ce trafic comme bénin, avec
une confiance élevée — et son avis était ignoré, puisqu'il n'intervenait qu'après
la décision d'alerter.

**Correction.** Une cascade : quand l'étage A signale un flux **marginal** que
l'étage B reconnaît comme normal avec ≥ 90 % de confiance, l'alerte est supprimée.
Au-dessus de 0,9975, jamais — sinon une attaque jamais apprise serait étouffée par
un classifieur qui ne la connaît pas.

**Mesure. 341 → 53 faux positifs/heure**, au prix de 0,6 point de rappel furtif.

---

## 3. Le parcours des flux actifs s'effondrait exactement quand il ne fallait pas

**Symptôme.** 12 000 paquets/s, avec un profil dominé à 80 % par `expire()`.

**Cause.** L'expiration parcourait tous les flux actifs **à chaque paquet**. Sous
inondation ou slowloris — dont le principe même est d'ouvrir des milliers de
connexions simultanées — ce parcours explose. Le détecteur ralentissait donc au
moment précis où il devait tenir.

**Correction.** Deux tas d'échéances paresseux, avec un compteur de génération par
flux pour reconnaître les entrées périmées au dépilage.

**Mesure.** 12 000 → **33 000 paquets/s**, et l'équivalence avec le parcours naïf
est vérifiée par un test sur 240 s de trafic mixte.

---

## 4. Un SYN sans réponse attendait 15 secondes pour rien

Une tentative de connexion restée sans réponse est **déjà une observation
complète** : plus rien n'arrivera jamais. La conserver pendant le délai
d'inactivité complet ajoutait 15 secondes à la détection de chaque balayage et de
chaque inondation — les deux attaques composées presque entièrement de SYN sans
réponse. Délai dédié de 3 s : latence médiane de détection **16 s → 3 s**.

---

## 5. La latence annoncée était fausse

Elle était mesurée depuis le **dernier paquet** du premier flux malveillant. Or un
analyste ne peut rien voir avant que l'assembleur n'ait **exporté** le flux. La
mesure ignorait donc le délai d'export — c'est-à-dire précisément la latence
propre à une détection par flux.

`Flow.export_ts` a été ajouté et la métrique s'appuie dessus. La latence médiane
publiée est passée de 0,67 s à **3,0 s**. Le système n'a pas ralenti ; le chiffre
est devenu vrai.

---

## 6. Le générateur produisait des trames physiquement impossibles

**Symptôme.** Un trafic écrit dans un `.pcap` puis relu ne redonnait pas les mêmes
flux : 1,2 % des paquets changeaient de taille.

**Cause.** La session SSH interactive tirait **deux** nombres aléatoires
indépendants : l'un pour la taille de trame annoncée, l'autre pour la longueur de
la charge utile. Elle émettait donc des trames déclarant 206 octets tout en en
transportant 256.

En mémoire personne ne s'en plaignait. Au moment d'écrire un vrai pcap, il a bien
fallu trancher — et l'incohérence est devenue visible.

**Correction.** Un seul tirage par paquet, utilisé pour les deux. Un test vérifie
désormais l'invariant sur l'ensemble du trafic généré.

---

## 7. Le même scénario ne produisait pas les mêmes octets selon le processus

Les charges utiles « chiffrées » venaient de `os.urandom`. Deux exécutions avec la
**même graine** produisaient donc les mêmes flux avec des octets différents : une
capture écrite par un processus devenait incomparable au trafic généré par un
autre, ce qui rendait toute vérification du rejeu impossible.

Remplacé par un tirage pseudo-aléatoire ensemencé. L'entropie est identique ; la
reproductibilité, elle, existe désormais — et un test la vérifie.

---

## 8. Le générateur bloquait le démarrage de l'API

Il planifiait toutes les sessions d'une période à l'avance. Demander 24 heures de
trafic revenait à construire près d'un demi-million de générateurs avant d'émettre
le premier paquet. Construction par tranches de 600 s : premier paquet en 0,16 s.

---

## 9. L'écriture en base mourait sur un compteur à `None`

SQLAlchemy applique les valeurs par défaut d'une colonne **à l'INSERT**, pas à la
construction de l'objet. Une ligne `Host` fraîchement créée contenait donc `None`,
et le premier `+=` tuait la tâche d'ingestion — silencieusement, puisque
l'exception était capturée et rangée dans l'état du pipeline.

Compteurs initialisés explicitement, et un test qui exerce le **vrai** chemin
d'écriture : un test unitaire sur l'écrivain n'aurait rien vu.

---

## 10. Le graphique principal était saturé par construction

Il affichait le score **maximum** par seconde. Or, les scores étant des
percentiles du trafic normal, le maximum de N flux est proche de 1 presque chaque
seconde : **58 % des secondes dépassaient 0,95 sans que rien ne se passe**. Un
graphique collé à son plafond apprend à l'opérateur à ne plus le regarder.

Le score **moyen** est devenu la série principale — il varie réellement de 0,16 à
0,99 — et le maximum reste en série secondaire, où son comportement saturé est
lisible pour ce qu'il est.

---

## 11. L'interface restait figée sur l'ancien code après un déploiement

`index.html` est le seul fichier dont le nom ne change jamais. Servi avec un cache
par défaut, il épinglait le navigateur sur les noms de ressources du build
précédent : l'application continuait d'exécuter l'ancien code sans que rien ne le
signale. `no-cache` sur la coquille, `immutable` sur les ressources horodatées par
empreinte.

---

## 12. Le rejeu de PCAP était inutilisable

Scapy décodait 3 200 paquets/s : une capture d'un million de paquets imposait cinq
minutes d'attente avant le premier flux. Un lecteur direct en `struct` pour le cas
courant (pcap classique, Ethernet + IPv4), avec repli sur scapy pour tout le reste :
**99 000 paquets/s**, soit 31×.

L'écriture a suivi le même chemin : scapy mettait plus de dix minutes à produire
une capture de 300 s. Un écrivain direct, avec un *snaplen* qui conserve
l'intégralité de l'échantillon de charge utile, la produit en 15 s.
