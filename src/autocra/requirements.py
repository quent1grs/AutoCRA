"""Référentiel des 22 exigences de l'annexe I du règlement (UE) 2024/2847.

Les intitulés résument le texte ; ils ne le citent pas. La colonne
« activités » décrit ce qu'AutoCRA fait pour réunir les preuves, et
« questions » ce que seul l'éditeur peut dire. À réviser quand les normes
EN 40000-1-3 et 1-4 seront publiées.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Requirement:
    id: str
    part: str  # "I" (produit) ou "II" (gestion des failles)
    ref: str  # référence dans l'annexe
    title: str
    objective: str
    preparation: str
    activities: tuple[str, ...]
    questions: tuple[str, ...] = field(default_factory=tuple)


REQUIREMENTS: tuple[Requirement, ...] = (
    # --- Annexe I, partie I : exigences sur le produit -------------------
    Requirement(
        "CRA-I-1-1", "I", "Annexe I, partie I, point 1",
        "Sécurité appropriée aux risques, dès la conception",
        "Montrer que le niveau de sécurité découle d'une analyse de risques écrite.",
        "Disposer de l'analyse de risques et de la description du produit.",
        ("Lister les données traitées, les points d'entrée et les appels sortants pour préparer l'analyse.",
         "Rechercher dans le dépôt une analyse de risques ou un modèle de menaces."),
        ("Existe-t-il une analyse de risques écrite et à jour ?",
         "Quel est l'usage prévu du produit et l'usage raisonnablement prévisible ?"),
    ),
    Requirement(
        "CRA-I-1-2a", "I", "Annexe I, partie I, point 2 a)",
        "Pas de faille exploitable connue à la mise sur le marché",
        "Montrer qu'aucune faille connue et exploitable n'affecte la version livrée.",
        "Inventaire des composants de la version livrée.",
        ("Produire l'inventaire des composants (SBOM).",
         "Comparer l'inventaire aux bases de failles publiques."),
        ("Les failles non corrigées ont-elles une justification (non exploitable, mesure compensatoire) ?",),
    ),
    Requirement(
        "CRA-I-1-2b", "I", "Annexe I, partie I, point 2 b)",
        "Configuration sûre par défaut et remise à l'état d'origine",
        "Montrer que les réglages par défaut sont sûrs et qu'une remise à zéro existe.",
        "Liste des réglages et de leurs valeurs par défaut.",
        ("Relever les réglages de sécurité et leur valeur par défaut.",
         "Rechercher les mots de passe ou comptes par défaut.",
         "Rechercher une fonction de remise à l'état d'origine."),
        ("Le produit est-il livré avec un compte ou un mot de passe par défaut ?",),
    ),
    Requirement(
        "CRA-I-1-2c", "I", "Annexe I, partie I, point 2 c)",
        "Correction des failles par mises à jour, automatiques par défaut si applicable",
        "Montrer qu'un mécanisme de mise à jour existe, notifie l'utilisateur et peut être reporté.",
        "Mode de distribution et d'installation du produit.",
        ("Rechercher un mécanisme de mise à jour et de vérification de signature.",
         "Rechercher une notification des mises à jour disponibles."),
        ("Comment le client reçoit-il les mises à jour de sécurité ?",
         "La mise à jour automatique est-elle applicable à ce produit ?"),
    ),
    Requirement(
        "CRA-I-1-2d", "I", "Annexe I, partie I, point 2 d)",
        "Protection contre les accès non autorisés",
        "Montrer que chaque point d'entrée est protégé et que les accès suspects sont signalés.",
        "Liste exhaustive des points d'entrée.",
        ("Énumérer tous les points d'entrée.",
         "Vérifier l'authentification et les droits sur chacun.",
         "Rechercher la limitation des tentatives et la journalisation des échecs."),
    ),
    Requirement(
        "CRA-I-1-2e", "I", "Annexe I, partie I, point 2 e)",
        "Confidentialité des données (chiffrement à l'état de l'art)",
        "Montrer que les données stockées, transmises et traitées sont protégées.",
        "Liste des données sensibles et de leurs lieux de stockage.",
        ("Rechercher les algorithmes faibles et les vérifications TLS désactivées.",
         "Rechercher les secrets écrits en clair dans le code.",
         "Relever le chiffrement en transit et au repos."),
    ),
    Requirement(
        "CRA-I-1-2f", "I", "Annexe I, partie I, point 2 f)",
        "Intégrité des données, commandes, programmes et réglages",
        "Montrer que les modifications non autorisées sont empêchées ou détectées.",
        "Liste des données et commandes critiques.",
        ("Rechercher les contrôles d'intégrité (signatures, sommes de contrôle, validation des entrées).",),
    ),
    Requirement(
        "CRA-I-1-2g", "I", "Annexe I, partie I, point 2 g)",
        "Minimisation des données",
        "Montrer que seules les données nécessaires sont traitées.",
        "Liste des données collectées et des appels sortants.",
        ("Relever les appels sortants et ce qu'ils envoient.",
         "Rechercher une télémétrie."),
        ("Quelles données personnelles le produit traite-t-il, et pourquoi ?",),
    ),
    Requirement(
        "CRA-I-1-2h", "I", "Annexe I, partie I, point 2 h)",
        "Disponibilité des fonctions essentielles",
        "Montrer la résistance aux dénis de service et la reprise après incident.",
        "Liste des fonctions essentielles.",
        ("Relever les limites de débit, de taille et de durée.",),
    ),
    Requirement(
        "CRA-I-1-2i", "I", "Annexe I, partie I, point 2 i)",
        "Ne pas nuire à la disponibilité d'autres services",
        "Montrer que les appels sortants sont bornés.",
        "Liste des appels sortants.",
        ("Relever les appels sortants et vérifier délais et relances.",),
    ),
    Requirement(
        "CRA-I-1-2j", "I", "Annexe I, partie I, point 2 j)",
        "Surface d'attaque limitée",
        "Montrer que chaque interface exposée est justifiée et que les fonctions inutiles sont désactivées.",
        "Liste exhaustive des interfaces exposées.",
        ("Énumérer routes, écouteurs réseau, arguments et variables d'environnement.",),
        ("Chaque interface listée est-elle nécessaire à l'usage prévu ?",),
    ),
    Requirement(
        "CRA-I-1-2k", "I", "Annexe I, partie I, point 2 k)",
        "Réduction de l'impact d'un incident",
        "Montrer le cloisonnement, le moindre privilège et les mécanismes d'atténuation.",
        "Architecture et mode d'exécution.",
        ("Relever l'utilisateur d'exécution des conteneurs et les options de durcissement.",),
    ),
    Requirement(
        "CRA-I-1-2l", "I", "Annexe I, partie I, point 2 l)",
        "Journalisation de l'activité utile à la sécurité",
        "Montrer que les accès et modifications sont enregistrés, avec possibilité de désactivation.",
        "Description du journal.",
        ("Rechercher un journal d'audit et ce qu'il couvre.",),
    ),
    Requirement(
        "CRA-I-1-2m", "I", "Annexe I, partie I, point 2 m)",
        "Suppression et transfert des données par l'utilisateur",
        "Montrer qu'un utilisateur peut effacer et exporter ses données.",
        "Liste des données utilisateur.",
        ("Rechercher les fonctions de suppression et d'export.",),
    ),
    # --- Annexe I, partie II : gestion des failles -----------------------
    Requirement(
        "CRA-II-1", "II", "Annexe I, partie II, point 1",
        "Inventaire des composants (SBOM)",
        "Montrer qu'un inventaire lisible par machine est produit, au moins pour les dépendances directes.",
        "Accès au dépôt et aux manifestes de dépendances.",
        ("Générer l'inventaire au format CycloneDX.",
         "Rechercher sa génération dans la chaîne de livraison."),
    ),
    Requirement(
        "CRA-II-2", "II", "Annexe I, partie II, point 2",
        "Correction rapide, mises à jour de sécurité séparées",
        "Montrer que les failles sont corrigées sans délai.",
        "Historique des versions et des avis de sécurité.",
        ("Rechercher un outil de mise à jour automatique des dépendances.",),
        ("Quel délai de correction visez-vous, et le tenez-vous ?",),
    ),
    Requirement(
        "CRA-II-3", "II", "Annexe I, partie II, point 3",
        "Tests et revues de sécurité réguliers",
        "Montrer que la sécurité est testée régulièrement.",
        "Chaîne de livraison.",
        ("Rechercher les tests automatiques et l'analyse de code dans la chaîne de livraison.",),
        ("Des tests d'intrusion ou revues externes ont-ils eu lieu ?",),
    ),
    Requirement(
        "CRA-II-4", "II", "Annexe I, partie II, point 4",
        "Publication des failles corrigées",
        "Montrer que les failles corrigées sont publiées avec description, impact, gravité et correctif.",
        "Avis de sécurité publiés.",
        ("Rechercher la publication d'avis de sécurité.",),
    ),
    Requirement(
        "CRA-II-5", "II", "Annexe I, partie II, point 5",
        "Politique de divulgation coordonnée",
        "Montrer qu'une politique existe et est appliquée.",
        "Document de politique.",
        ("Rechercher la politique de sécurité dans le dépôt.",),
        ("La politique est-elle appliquée, avec quels délais de réponse ?",),
    ),
    Requirement(
        "CRA-II-6", "II", "Annexe I, partie II, point 6",
        "Contact pour signaler une faille",
        "Montrer qu'une adresse de contact est publiée.",
        "Documents publics du produit.",
        ("Rechercher security.txt et une adresse de contact.",),
    ),
    Requirement(
        "CRA-II-7", "II", "Annexe I, partie II, point 7",
        "Distribution sûre des mises à jour",
        "Montrer que les livrables sont signés et vérifiés.",
        "Chaîne de livraison.",
        ("Rechercher la signature des livrables et sa vérification.",),
    ),
    Requirement(
        "CRA-II-8", "II", "Annexe I, partie II, point 8",
        "Diffusion gratuite et rapide des correctifs",
        "Montrer que les correctifs sont diffusés sans délai, gratuitement, avec un message.",
        "Notes de version.",
        ("Rechercher les notes de version.",),
        ("Les correctifs de sécurité sont-ils gratuits pour tous les clients ?",),
    ),
)

BY_ID: dict[str, Requirement] = {r.id: r for r in REQUIREMENTS}


def get(requirement_id: str) -> Requirement:
    return BY_ID[requirement_id]
