# Analyse de risques d'AutoCRA

Version 0.1 du 11 novembre 2026. Première version, à revoir à chaque fonction nouvelle et au moins une fois par trimestre.
Rédigée pour l'article 13, paragraphes 2 et 3, du règlement (UE) 2024/2847 : l'analyse de risques guide la conception et accompagne le produit.

## Ce qu'est le produit

AutoCRA est un outil en ligne de commande. Il lit le code d'un produit, relève des éléments avec Semgrep et Syft, et prépare des fiches de preuve pour les exigences de l'annexe I. En option, il fait lire des extraits de code par un modèle d'IA. Une personne décide de l'état de chaque fiche.

**Usage prévu** : sur le poste ou le serveur d'un éditeur de logiciel ou d'un auditeur, par une personne autorisée à lire le code analysé.

**Mauvais usage prévisible** : prendre l'état proposé par l'outil pour une déclaration de conformité ; analyser un code que l'on n'a pas le droit de lire ; publier le rapport.

## Ce qu'il faut protéger

| Bien | Pourquoi |
|---|---|
| Le code analysé | Secret d'affaires du client |
| Le rapport et les fiches | Liste des points faibles d'un produit |
| Le journal des décisions | Preuve de qui a validé quoi |
| L'intégrité de l'outil et de ses règles | Un outil modifié donne des preuves fausses |
| La clé d'accès au modèle d'IA | Donne accès à un compte payant |

## Surface exposée

- Aucun port réseau ouvert, aucun service en écoute.
- Entrées : arguments de la ligne de commande, fichiers du dépôt analysé, réponses du modèle d'IA, fichiers `reponses/` en mode hors ligne.
- Sorties réseau : aucune par défaut. Avec `--ia`, des extraits de code partent vers le fournisseur du modèle.
- Programmes appelés : `semgrep`, `syft`, `git`.

## Risques et traitement

| N° | Risque | Gravité | Traitement en place | Reste à faire |
|---|---|---|---|---|
| R1 | Le code du client sort de chez lui lors de la lecture par l'IA | Élevée | La lecture par l'IA est éteinte par défaut ; mode hors ligne ; télémétrie de Semgrep coupée | Modèle hébergé chez le client ; engagement écrit du fournisseur ; avertissement avant le premier envoi |
| R2 | Le code analysé contient un texte qui manipule le modèle | Élevée | Citations hors extraits écartées ; décision humaine obligatoire | Jeu d'essai d'injection ; double lecture par deux modèles |
| R3 | L'outil manque un élément et la fiche rassure à tort | Élevée | États jamais conclusifs ; « absence non prouvée » ; compte des éléments non montrés | Mesure du taux d'oubli sur des projets connus |
| R4 | Le rapport est lu par un tiers | Moyenne | Écrit seulement dans le dossier choisi par l'utilisateur | Droits de fichier restreints ; option de chiffrement |
| R5 | Un fichier du dépôt analysé fait exécuter du code à l'outil | Élevée | Les fichiers sont lus, jamais exécutés ; Semgrep limité à nos règles ; taille des fichiers bornée | Revue des appels de programmes ; essai sur un dépôt piégé |
| R6 | Une dépendance compromise (Semgrep, Syft, paquets Python) | Élevée | Peu de dépendances ; inventaire des composants produit par l'outil | Versions figées ; recherche de failles connues ; vérification de l'empreinte de Syft |
| R7 | Le journal des décisions est modifié après coup | Moyenne | Journal en ajout seul côté outil | Chaînage par empreintes ou signature |
| R8 | Fuite de la clé d'accès au modèle | Moyenne | Lue dans l'environnement, jamais écrite dans les sorties | Vérifier qu'elle n'apparaît dans aucun message d'erreur |
| R9 | Une version modifiée de l'outil est distribuée | Élevée | Aucun | Signature des versions ; publication par la chaîne de livraison |

## Décisions de conception qui en découlent

1. Tout tourne en local. Rien ne sort sans une option explicite.
2. L'outil ne déclare jamais la conformité.
3. Chaque preuve porte un fichier, une ligne et la version du code.
4. Le code analysé est une donnée, jamais une instruction.

## Ce qui n'est pas couvert

Cette version ne traite pas l'hébergement d'un service en ligne, qui n'existe pas. Elle n'a pas été relue par une personne extérieure au projet.
