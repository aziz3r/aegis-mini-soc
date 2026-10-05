# Guide de démonstration

Comment montrer AEGIS en dix minutes, et quoi dire à chaque écran.

---

## Avant

```bash
./scripts/demo.sh
```

Laissez tourner deux à trois minutes avant de commencer : le moteur a besoin de
voir du trafic normal pour calibrer les seuils par hôte, exactement comme une
sonde qu'on vient de déployer. Les attaques sont planifiées aléatoirement dans
chaque tranche de 600 s simulées ; à vitesse ×6, comptez une à deux minutes avant
les premiers incidents.

Ouvrez **http://127.0.0.1:8000** et connectez-vous en `admin`.

---

## 1. Vue d'ensemble — « que se passe-t-il ? »

Les quatre tuiles de gravité portent **une icône et un mot**, jamais une couleur
seule : rouge, orange et jaune sont voisins sur la roue chromatique et illisibles
pour un daltonien.

Pointez le ratio sous « alertes corrélées » — souvent **plus de 200 pour 1**.
C'est la mesure directe de ce que la corrélation évite à l'analyste.

Le graphique porte deux séries : le score **moyen** du trafic, qui varie
réellement, et le score du **flux le plus anormal**, qui reste collé au plafond.
Ce n'est pas un défaut d'affichage : les scores étant des percentiles du trafic
normal, le maximum de N flux est proche de 1 presque chaque seconde. C'est
précisément pourquoi le seuil s'applique **par flux** et pourquoi l'étage B
oppose un veto — sans quoi le système alerterait en permanence.

## 2. Flux temps réel — « la chaîne tourne »

Tout bouge en direct par WebSocket. La tuile **« supprimées par l'étage B »** est
celle qui mérite un commentaire : ce sont les anomalies que le classifieur a
reconnues comme du trafic normal. Elles valent **six faux positifs évités sur
sept** (341 → 53 par heure).

## 3. Incidents — « par quoi commencer ? »

Le tri est sur la **priorité**, pas sur le score. Un balayage de ports contre le
serveur de base de données passe devant un balayage plus bruyant contre une
imprimante, parce que la priorité combine la marge au-dessus du seuil *de cet
hôte*, la criticité de l'actif et la confiance du classifieur.

Vous verrez souvent une ligne **« Trafic normal »**. C'est un faux positif, et il
est affiché comme tel : l'étage A l'a signalé, l'étage B l'a jugé bénin, mais son
score dépassait 0,9975 — au-dessus de ce seuil, on alerte quoi qu'il arrive,
parce que c'est ce qui préserve la détection d'une attaque jamais apprise.
L'honnêteté de cet affichage est un choix, pas un oubli.

## 4. Détail d'un incident — **le moment à ne pas rater**

Ouvrez un tunnel DNS ou un balayage. Le panneau **« Pourquoi cette alerte »**
donne quelque chose comme :

> *répétitions vers une même cible — mesuré 197, référence 2 — ↑ au-dessus de la normale*
> *flux reçus par la cible (10 s) — mesuré 163, référence 10*

Chaque feature a été remplacée tour à tour par sa valeur médiane sur le trafic
normal et le flux réévalué ; la chute du score mesure sa contribution. Un analyste
comprend en deux secondes, sans croire le modèle sur parole.

Plus bas : le guide de traitement MITRE, les ports visés, les pairs impliqués, et
— puisque la source est le laboratoire — la **vérité terrain**, qui dit si ces
alertes correspondaient vraiment à une attaque.

Faites le triage : « Prendre en compte », puis « Vrai positif ». L'incident se
ferme, et le jugement est enregistré comme signal de ré-entraînement.

## 5. Modèle — « pourquoi vous croire ? »

Deux colonnes, bruyant et furtif. Les chiffres bruyants disent que la chaîne
fonctionne ; les furtifs disent **où elle cesse de fonctionner**.

Le point à montrer est la **balise C2 à 48 % de rappel**. C'est le résultat le
plus instructif du tableau : une balise émet quelques centaines d'octets toutes
les dizaines de secondes vers un port banal, et chacun de ses flux ressemble
isolément à une requête web. Seule la périodicité la trahit. Publier ce 48 % à
côté des 99 % des autres familles est ce qui distingue une mesure d'une
démonstration commerciale.

Montrez aussi le tableau des **seuils par hôte** : quelques hôtes ont relevé leur
propre barre au-dessus du plancher. Leur trafic normal est légitimement
inhabituel, et c'est exactement ce que l'adaptation évite de signaler en boucle.

## 6. Sources & rejeu — « ce n'est pas qu'une simulation »

Le plan d'attaque de la tranche en cours est affiché : famille, instant, durée,
mode. C'est la vérité terrain, connue à l'avance, qui permet de vérifier que le
tableau de bord décrit bien ce qui s'est passé.

Puis l'argument décisif :

```bash
aegis export-pcap --duration 300
```

Le fichier produit s'ouvre dans Wireshark. Rejouez-le depuis l'onglet
« Rejeu de PCAP » : le moteur ne fait aucune différence entre une capture et du
trafic en direct, et un test vérifie que les features structurelles sont
**identiques à 100 %** entre les deux chemins. La même commande accepterait une
capture réelle.

---

## Les trois questions qui viennent

**« Les chiffres ne sont-ils pas trop beaux ? »**
Si, pour les attaques bruyantes — et c'est dit dans le rapport. Le générateur
produit des comportements paramétriques distincts, donc séparables. C'est pour
cela que la colonne furtive existe, que la balise C2 est publiée à 48 %, et que
le rejeu de PCAP est la véritable épreuve.

**« Pourquoi pas CIC-IDS2017 ? »**
C'est l'évolution numéro un. Le jeu public est au niveau flux, pas paquet : il ne
peut pas exercer l'assemblage de flux, qui est la moitié du système. Le générateur
produit des **paquets**, donc toute la chaîne est exercée de bout en bout. Les
deux approches sont complémentaires, et le lecteur PCAP est déjà en place pour la
seconde.

**« Que se passe-t-il sur un vrai réseau ? »**
Davantage de faux positifs : un réseau réel est plus désordonné qu'un générateur.
Les trois leviers sont déjà là — le quantile par hôte, la confiance de veto de
l'étage B, et la fenêtre de corrélation — tous réglables depuis l'écran Réglages,
sans ré-entraînement, puisqu'ils ne touchent que le point de fonctionnement.
