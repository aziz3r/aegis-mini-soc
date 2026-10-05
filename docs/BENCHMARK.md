# Résultats de référence — AEGIS Mini-SOC

> Fichier **généré** par `aegis train` / `aegis bench`. Ne pas éditer à la main :
> il est réécrit à chaque entraînement pour qu'il décrive toujours le modèle
> réellement présent dans `stage_a_isoforest.joblib`.

- Modèle entraîné le : `2026-10-03T16:30:14+00:00`
- Captures d'entraînement (seeds) : `[11, 12, 13, 14, 15, 16]`
- Captures de test (seeds) : `[901, 902, 903]` — **disjoints**
- Flux bénins vus par l'étage A : 22,295
- Flux étiquetés vus par l'étage B : 19,397
- Nombre de features : 52
- Seuil plancher : 0.98 (percentile du trafic bénin)

## Protocole

1. L'étage A (IsolationForest) n'est entraîné que sur du **trafic bénin**.
2. L'étage B (HistGradientBoosting) est entraîné sur des captures étiquetées,
   plafonnées par classe pour qu'une seule inondation ne représente pas la
   majorité du jeu de données.
3. La séparation train/test se fait **par capture** (par « journée simulée »),
   jamais par ligne : des flux issus de la même rafale d'attaque sont très
   corrélés, et un découpage aléatoire produirait des scores illusoires.
4. Le point de fonctionnement est mesuré en **rejouant les captures de test
   dans le moteur réel**, seuils adaptatifs compris, préchauffés sur une
   capture bénigne comme le serait une sonde déployée.
5. Les faux positifs sont mesurés sur des captures **sans aucune attaque**.

## Détection

| Mesure | Attaques bruyantes | Attaques furtives |
|---|---|---|
| Rappel | 99.56 % | 95.94 % |
| Précision | 99.89 % | 98.57 % |
| F1 | 0.9973 | 0.9724 |
| PR-AUC | 0.9955 | 0.9373 |
| Latence médiane | 2.0 s | 6.0 s |
| Latence p95 | 120.0 s | 120.0 s |

- ROC-AUC (bruyant) : **0.9959**
- Matrice de confusion binaire : VP 45,070 · FP 49 · FN 199 · VN 11,014
- Débit mesuré : **30,206 paquets/s** (mono-processus)

### Pourquoi deux colonnes

Les variantes « furtives » sont les mêmes attaques ralenties d'un facteur 15 à 60,
avec rotation des sources, variation des tailles de requête et gigue de 25 % sur les
balises. Les chiffres bruyants disent que la chaîne fonctionne ; les chiffres furtifs
disent où elle cesse de fonctionner. Un rapport qui ne publie que la première colonne
ne mesure pas un détecteur, il mesure un générateur de trafic.

## Charge d'alerte sur trafic normal

- Flux bénins évalués : 11,004
- Part des flux bénins qui alertent : 0.29 %
- **54 alertes/heure** avant corrélation
- **54.2 incidents/heure** après corrélation

La seconde valeur est celle qui compte : c'est le nombre de lignes de travail
effectives pour un analyste. L'écart entre les deux est exactement ce que la
corrélation apporte.

## Rappel par famille d'attaque

| Famille | MITRE | Rappel (bruyant) | Rappel (furtif) | n (bruyant) |
|---|---|---|---|---|
| C2_BEACON | `T1071.001` | 48.62 % | 72.73 % | 109 |
| DNS_TUNNEL | `T1071.004` | 99.67 % | 96.87 % | 3,629 |
| DOS_FLOOD | `T1498` | 99.50 % | 95.11 % | 19,538 |
| EXFILTRATION | `T1041` | 100.00 % | 100.00 % | 277 |
| NET_SCAN | `T1018` | 99.93 % | 99.29 % | 10,524 |
| PORT_SCAN | `T1046` | 99.93 % | 79.79 % | 5,378 |
| SLOWLORIS | `T1499.003` | 100.00 % | 100.00 % | 584 |
| SSH_BRUTEFORCE | `T1110.001` | 99.69 % | 96.67 % | 2,549 |
| WEB_BRUTEFORCE | `T1110.004` | 99.48 % | 96.74 % | 2,681 |

## Nommage de la famille (étage B)

macro-F1 : **0.9997** (bruyant) · **0.9171** (furtif)

| Famille | Précision | Rappel | F1 | n |
|---|---|---|---|---|
| PORT_SCAN | 0.997 | 1.000 | 0.999 | 5,378 |
| NET_SCAN | 1.000 | 0.999 | 0.999 | 10,524 |
| DOS_FLOOD | 1.000 | 1.000 | 1.000 | 19,538 |
| SSH_BRUTEFORCE | 1.000 | 1.000 | 1.000 | 2,549 |
| WEB_BRUTEFORCE | 1.000 | 1.000 | 1.000 | 2,681 |
| SLOWLORIS | 1.000 | 1.000 | 1.000 | 584 |
| DNS_TUNNEL | 1.000 | 1.000 | 1.000 | 3,629 |
| EXFILTRATION | 1.000 | 1.000 | 1.000 | 277 |
| C2_BEACON | 1.000 | 1.000 | 1.000 | 109 |

### Matrice de confusion

| vérité \ prédit | PORT_SCAN | NET_SCAN | DOS_FLOOD | SSH_BRUTEFORCE | WEB_BRUTEFORCE | SLOWLORIS | DNS_TUNNEL | EXFILTRATION | C2_BEACON | UNKNOWN | BENIGN |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **PORT_SCAN** | 5378 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **NET_SCAN** | 16 | 10508 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **DOS_FLOOD** | 0 | 0 | 19538 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **SSH_BRUTEFORCE** | 0 | 0 | 0 | 2549 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **WEB_BRUTEFORCE** | 0 | 0 | 0 | 0 | 2680 | 0 | 0 | 0 | 0 | 0 | 1 |
| **SLOWLORIS** | 0 | 0 | 0 | 0 | 0 | 584 | 0 | 0 | 0 | 0 | 0 |
| **DNS_TUNNEL** | 0 | 0 | 0 | 0 | 0 | 0 | 3629 | 0 | 0 | 0 | 0 |
| **EXFILTRATION** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 277 | 0 | 0 | 0 |
| **C2_BEACON** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 109 | 0 | 0 |
| **UNKNOWN** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **BENIGN** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

## Limites à connaître

1. **Le trafic est synthétique.** La chaîne de détection (assemblage de flux,
   features, modèle, seuils, corrélation) est réelle et c'est la même qui tourne
   en production ; le trafic qui l'alimente est généré. Un vrai réseau est plus
   désordonné : attendez-vous à davantage de faux positifs qu'ici.
2. **Les familles sont séparables par construction.** Le générateur produit des
   comportements paramétriques distincts, ce qui explique les scores très élevés
   de l'étage B sur les variantes bruyantes. La colonne « furtive » est la mesure
   honnête, et `aegis replay` sur un PCAP réel est la vraie épreuve.
3. **La latence inclut le délai d'export des flux** (3 s pour une tentative de
   connexion sans réponse, 15 s d'inactivité sinon, 120 s pour un flux long).
   C'est le compromis inhérent à une détection par flux plutôt que par paquet.
4. **Les sources usurpées** ne sont détectables que côté destination : c'est le
   rôle des quatre features `dst_*`.

_Généré le 2026-10-03T16:30:16+00:00._
