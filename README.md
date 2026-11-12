# AutoCRA

Moteur de preuves pour le Cyber Resilience Act, règlement (UE) 2024/2847.

AutoCRA lit le code d'un produit et réunit, pour chacune des 22 exigences de
l'annexe I, des preuves localisées (fichier, ligne, version du code). Il ne
déclare jamais la conformité : il prépare le dossier, une personne décide.

## Principes

- **Tout tourne en local.** Le code analysé ne quitte pas la machine. Semgrep
  est lancé sans compte et sans envoi de métriques.
- **Trois sources de preuve.** Un outil énumère (exhaustif, reproductible),
  l'IA lit et explique (à venir), un humain conclut.
- **Preuves pour et contre.** Chaque exigence montre les éléments favorables,
  défavorables et ceux qui restent à juger.
- **Une absence de résultat n'est pas une preuve d'absence.**

## Installation

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

L'inventaire des composants utilise [Syft](https://github.com/anchore/syft)
(facultatif, option `--syft` ou exécutable dans le PATH).

## Utilisation

```bash
autocra scan chemin/du/depot -o sortie
autocra requirements
```

Le dossier de sortie contient :

- `rapport.md` : rapport lisible, une fiche par exigence ;
- `questionnaire.md` : les questions que seul l'éditeur peut trancher ;
- `preuves.json` : toutes les preuves, pour un traitement automatique ;
- `sbom.cdx.json` : inventaire des composants au format CycloneDX.

### Lecture par l'IA

```bash
pip install -e ".[ia]"
export ANTHROPIC_API_KEY=...            # compte API, distinct d'un abonnement Claude
autocra scan chemin/du/depot -o sortie --ia --only CRA-I-1-2b,CRA-I-1-2e
```

Pour chaque exigence, le modèle reçoit des extraits numérotés autour des
éléments relevés par les outils et rend un état proposé, une synthèse, des
éléments pour et contre avec fichier et ligne, et ce qu'il reste à lire.

- Toute citation hors des extraits fournis est marquée « non vérifiée » et
  écartée des preuves.
- Les éléments non montrés au modèle, faute de place, sont comptés dans la
  fiche (« couverture »).
- `--model` choisit le modèle (défaut `claude-opus-5-5`), `--only` limite les
  exigences lues, donc le coût.

`--ia-hors-ligne` écrit les messages dans `sortie/prompts/` et lit les
réponses dans `sortie/reponses/<exigence>.json`. Ce mode sert à faire lire
les extraits par un autre modèle, y compris hébergé chez le client, sans
qu'aucun code ne sorte de la machine.

Par défaut, les dossiers de tests, de documentation et de migrations sont
exclus. `--include-tests` les réintègre.

### Faire relire par un second modèle

Une seule lecture laisse passer des éléments. Pour comparer deux lectures, placez les réponses du second modèle dans `sortie/reponses-contre-lecture/<exigence>.json`, au même format, puis :

```
autocra scan chemin/du/depot -o sortie --ia-hors-ligne --contre-lecture
```

Le rapport indique pour chaque exigence si les deux lectures s'accordent, les lignes classées en sens contraire et ce que chacune a relevé seule. Une contre-lecture peut ne porter que sur quelques exigences.

Si le code analysé contient un texte qui semble s'adresser à un modèle d'IA, la fiche porte une alerte.

### Enregistrer la décision d'une personne

L'outil propose, une personne décide. Chaque décision est notée avec son auteur, sa date et la version du code :

```
autocra valider CRA-I-1-2d --etat partielle --par "Prénom Nom" --note "Réserve sur le lien de partage" --code chemin/du/depot -o sortie
```

Les décisions sont gardées dans `sortie/decisions.json`, sans jamais effacer les précédentes. Au prochain `autocra scan`, le rapport affiche la décision de chaque fiche et signale celles prises sur une version du code qui a changé depuis.

## Ce que fait la version 0.1

| Collecteur | Ce qu'il trouve | Exigences |
|---|---|---|
| Semgrep, règles d'inventaire | Routes, écouteurs réseau, arguments, variables d'environnement, appels sortants, réglages Django, secrets en dur, cryptographie, journal d'audit | 2(b) à 2(m) |
| Fichiers du dépôt | Politique de sécurité, contact, mise à jour des dépendances, tests et analyse dans la chaîne de livraison, signature, utilisateur du conteneur | Partie II, 2(k) |
| Syft | Inventaire des composants | 2(a), partie II point 1 |

Langages couverts : Python (Django, DRF, Flask, FastAPI) et JavaScript ou
TypeScript (Express, Node.js, Socket.IO).

## Limites connues

- Les règles ne voient que les formes simples. Un réglage calculé par une
  fonction (par exemple `DEBUG = get_bool("DEBUG")`) n'est pas jugé.
- Aucune recherche de failles connues dans les composants pour l'instant.
- La lecture par l'IA ne voit que les extraits autour des éléments relevés. Ce que
  les règles n'ont pas relevé ne lui est pas montré.
- La lecture par l'IA n'a pas encore été essayée avec une clé réelle : seul le
  mode hors ligne a tourné de bout en bout.
- Les intitulés des exigences résument le règlement et ne le citent pas.

## Tests

```
./scripts/verifier.sh
```

Le script lance les tests, puis applique AutoCRA à son propre code. Il est à lancer avant chaque envoi : les tests ne tournent pas encore automatiquement sur GitHub.

## Préparer une version

```
./scripts/publier.sh                     # paquet et empreintes
./scripts/publier.sh cle-privee.pem      # paquet et empreintes signées
```

Le script refuse un dépôt modifié, lance la vérification, construit le paquet dans `dist/`, note la version du code et calcule les empreintes SHA-256. Avec une clé privée Ed25519, il signe le fichier d'empreintes. Le client vérifie avec `sha256sum -c SHA256SUMS`, puis la signature avec `openssl pkeyutl -verify` et la clé publique de l'éditeur. Les commandes exactes sont en tête du script. La clé privée ne doit jamais entrer dans le dépôt.
