"""Ligne de commande d'AutoCRA."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, decisions, engine, report, requirements


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="autocra",
        description="Prépare des preuves localisées pour les exigences du Cyber Resilience Act.",
    )
    parser.add_argument("--version", action="version", version=f"autocra {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Analyser un dépôt de code")
    scan.add_argument("target", type=Path, help="Dossier du code à analyser")
    scan.add_argument("-o", "--out", type=Path, default=Path("autocra-out"), help="Dossier de sortie")
    scan.add_argument("--syft", help="Chemin de l'exécutable Syft")
    scan.add_argument("--include-tests", action="store_true",
                      help="Analyser aussi les dossiers de tests et de documentation")
    scan.add_argument("--ia", action="store_true",
                      help="Faire lire les extraits par un modèle d'IA (nécessite ANTHROPIC_API_KEY)")
    scan.add_argument("--ia-hors-ligne", action="store_true",
                      help="Écrire les messages dans <sortie>/prompts et lire les réponses dans <sortie>/reponses")
    scan.add_argument("--contre-lecture", action="store_true",
                      help="Comparer avec une seconde lecture, lue dans <sortie>/reponses-contre-lecture")
    scan.add_argument("--model", help="Modèle à utiliser pour la lecture (défaut : claude-opus-5-5)")
    scan.add_argument("--only", help="Limiter la lecture par l'IA à ces exigences, séparées par des virgules")
    scan.add_argument("--no-sbom", action="store_true", help="Ne pas produire l'inventaire des composants")

    sub.add_parser("requirements", help="Lister les exigences du référentiel")

    valider = sub.add_parser("valider", help="Enregistrer la décision d'une personne sur une fiche")
    valider.add_argument("reference", help="Exigence concernée, par exemple CRA-I-1-2d")
    valider.add_argument("--etat", required=True, choices=[s.value for s in decisions.HUMAN_STATUSES],
                         help="État retenu par la personne")
    valider.add_argument("--par", required=True, help="Nom de la personne qui décide")
    valider.add_argument("--note", default="", help="Justification ou réserve")
    valider.add_argument("--code", type=Path, required=True, help="Dossier du code analysé (pour noter sa version)")
    valider.add_argument("-o", "--out", type=Path, default=Path("autocra-out"), help="Dossier de sortie de l'analyse")

    args = parser.parse_args(argv)

    if args.command == "requirements":
        for req in requirements.REQUIREMENTS:
            print(f"{req.id:12} {req.title}")
        return 0

    if args.command == "valider":
        try:
            decision = decisions.record(args.out, args.reference, args.etat, args.par,
                                        engine.git_commit(args.code.resolve()), args.note)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(f"Décision enregistrée : {decision.reference} = {decision.status}, par {decision.author}, "
              f"version {(decision.commit or 'inconnue')[:12]}.")
        print("Relancez « autocra scan » pour mettre le rapport à jour.")
        return 0

    if not args.target.is_dir():
        print(f"Dossier introuvable : {args.target}", file=sys.stderr)
        return 2
    reader = None
    if args.ia:
        from .reader import default_reader
        reader = default_reader(args.model)
    elif args.ia_hors_ligne:
        from .reader import FileReader
        reader = FileReader(args.out)
    second_reader = None
    if args.contre_lecture:
        from .reader import FileReader
        second_reader = FileReader(args.out, answers="reponses-contre-lecture", name="contre-lecture hors ligne")
    analysis = engine.analyse(args.target, args.out, syft=args.syft, with_sbom=not args.no_sbom,
                              excludes=() if args.include_tests else None, reader=reader,
                              second_reader=second_reader,
                              only=tuple(args.only.split(",")) if args.only else None)
    report.write_json(analysis, args.out / "preuves.json")
    report.write_markdown(analysis, args.out / "rapport.md")
    report.write_questionnaire(analysis, args.out / "questionnaire.md")

    print(f"Analyse terminée : {len(analysis.findings)} éléments pour {len(analysis.evidences)} exigences.")
    for category, count in sorted(analysis.counts().items()):
        print(f"  {report.CATEGORY_LABELS.get(category, category)} : {count}")
    if analysis.errors:
        print(f"  {len(analysis.errors)} erreur(s) d'analyse, voir le rapport.")
    print(f"Rapport : {args.out / 'rapport.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
