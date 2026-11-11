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

Par défaut, les dossiers de tests, de documentation et de migrations sont
exclus. `--include-tests` les réintègre.

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
- Pas encore de lecture par l'IA : les états proposés restent « à examiner ».
- Les intitulés des exigences résument le règlement et ne le citent pas.

## Tests

```bash
pytest
```
