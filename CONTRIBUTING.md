# Travailler sur AEGIS Mini-SOC

## Stratégie de branches

Le projet suit un **GitHub Flow** : une branche stable, des branches courtes.

```
main ──────●──────────●────────────────●──────────►  toujours fonctionnelle
            \        /                /
             ●──●──●                 /               feat/derive-du-modele
                                    /
                        ●──●───────●                 fix/seuil-plafonne
```

| Branche | Rôle |
|---|---|
| `main` | seule branche durable. L'intégration continue doit y être verte. |
| `feat/<sujet>` | une fonctionnalité. Exemples : `feat/rejeu-cicids`, `feat/suivi-de-derive`. |
| `fix/<sujet>` | une correction. Exemple : `fix/seuil-plafonne`. |
| `docs/<sujet>` | documentation seule. |

Les branches sont **courtes** : quelques jours au plus. Une branche qui vit trois
semaines diverge de `main`, et la fusion devient un travail en soi.

## Le cycle

```bash
git switch -c feat/suivi-de-derive
# … travail …
make test-fast                       # retour en quelques secondes
make lint                            # TypeScript strict
make schemas                         # si un schéma a bougé
git commit
git push -u origin feat/suivi-de-derive
gh pr create
```

L'intégration continue rejoue les mêmes contrôles sur la demande de fusion, plus
la suite complète et la compilation de l'interface. Elle doit être verte avant
de fusionner.

## Messages de commit

Préfixes conventionnels, puis un corps qui explique **pourquoi** — le *quoi* se
lit déjà dans le diff.

```
feat(core): expiration des flux par tas d'échéances

Le parcours de la table des flux actifs coûtait O(n) par paquet et
s'effondrait précisément sous inondation, où des milliers de connexions
simultanées sont le principe même de l'attaque. 12k -> 33k paquets/s.

L'équivalence avec le parcours naïf est vérifiée par un test : une
optimisation non prouvée est un bug qui attend.
```

Préfixes : `feat`, `fix`, `docs`, `test`, `perf`, `refactor`, `chore`.

## Ce qu'il faut vérifier avant de proposer une fusion

| Contrôle | Commande | Ce qu'il attrape |
|---|---|---|
| Tests rapides | `make test-fast` | assemblage, features, API, rôles, écriture en base |
| Suite complète | `make test` | + calibration, seuils, corrélation, aller-retour PCAP |
| Types | `make lint` | TypeScript en mode strict |
| Schémas | `make schemas` | un texte qui déborde, un SVG qui ne correspond plus |
| Mesures | `make bench` | si le modèle ou les features ont changé |

## Toucher aux features ou au modèle

Toute modification de `FEATURE_NAMES` **invalide le modèle enregistré** : il
refuse de se charger, volontairement, parce qu'une colonne qui se décale
silencieusement est le pire mode de panne de ce système. Après un tel
changement :

```bash
make train     # réentraîne et régénère docs/BENCHMARK.md
```

Le fichier `docs/BENCHMARK.md` est **engendré** : ne l'éditez jamais à la main,
il est réécrit à chaque entraînement pour qu'il décrive toujours le modèle
réellement présent sur le disque.

## Toucher aux schémas

Les SVG de `docs/` sont engendrés depuis `docs/schemas/` : modifiez le
générateur, jamais le SVG. Les variantes claire et sombre viennent d'une seule
description, ce qui les empêche de diverger.

```bash
make schemas   # régénère et vérifie qu'aucun texte ne déborde
```

L'intégration continue refuse un envoi où les SVG versionnés ne correspondraient
plus à leurs générateurs.

## Toucher aux documents

Les PDF sont compilés depuis LaTeX par [tectonic](https://tectonic-typesetting.github.io/) :

```bash
brew install tectonic
make pdf       # convertit les schémas puis compile les deux documents
```

## Une règle de fond

Ce projet publie ses chiffres défavorables au même titre que les autres — le
rappel de 48,6 % sur la balise de commande et contrôle est dans le README, dans
les deux PDF et dans l'interface. Une modification qui améliore une mesure doit
dire **comment elle a été mesurée**, et à quel prix sur les autres.
