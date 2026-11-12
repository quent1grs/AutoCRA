# Politique de sécurité d'AutoCRA

## Signaler une faille

AutoCRA n'est pas encore diffusé publiquement. Si vous avez reçu l'outil et pensez avoir trouvé une faille, signalez-la **en privé** à la personne qui vous l'a remis. N'ouvrez pas de ticket public et ne publiez pas le détail.

Une adresse de contact dédiée sera publiée ici avant la première diffusion commerciale.

Un signalement utile contient :

- la version d'AutoCRA (`autocra --version`) et le système utilisé ;
- les étapes pour reproduire le problème ;
- ce qu'une personne malveillante pourrait en faire ;
- si possible, un dépôt d'essai minimal qui montre le problème.

## Ce à quoi nous nous engageons

- Accuser réception sous cinq jours ouvrés.
- Dire sous quinze jours ouvrés si le problème est confirmé et quand un correctif est prévu.
- Prévenir la personne qui a signalé avant toute publication, et la citer si elle le souhaite.
- Publier chaque faille corrigée dans les notes de version, avec sa gravité et la version qui la corrige.

## Versions prises en charge

Seule la dernière version publiée reçoit des correctifs de sécurité.

## Ce qui compte comme une faille d'AutoCRA

- Un dépôt analysé qui fait exécuter du code à l'outil ou lui fait écrire hors du dossier de sortie.
- Une sortie de données non demandée : code analysé, rapport, clé d'accès.
- Un texte placé dans le code analysé qui fait conclure l'IA à tort sans qu'aucune alerte n'apparaisse.
- Une modification du journal des décisions qui passe inaperçue.

Un élément manqué par les règles d'inventaire n'est pas une faille de sécurité : signalez-le comme un défaut ordinaire.

L'analyse de risques du produit est dans `docs/analyse-de-risques.md`.
