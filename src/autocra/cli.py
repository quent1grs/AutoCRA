"""Ligne de commande d'AutoCRA."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, engine, report, requirements


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
    scan.add_argument("--no-sbom", action="store_true", help="Ne pas produire l'inventaire des composants")

    sub.add_parser("requirements", help="Lister les exigences du référentiel")

    args = parser.parse_args(argv)

    if args.command == "requirements":
        for req in requirements.REQUIREMENTS:
            print(f"{req.id:12} {req.title}")
        return 0

    if not args.target.is_dir():
        print(f"Dossier introuvable : {args.target}", file=sys.stderr)
        return 2
    analysis = engine.analyse(args.target, args.out, syft=args.syft, with_sbom=not args.no_sbom,
                              excludes=() if args.include_tests else None)
    report.write_json(analysis, args.out / "preuves.json")
    report.write_markdown(analysis, args.out / "rapport.md")

    print(f"Analyse terminée : {len(analysis.findings)} éléments pour {len(analysis.evidences)} exigences.")
    for category, count in sorted(analysis.counts().items()):
        print(f"  {report.CATEGORY_LABELS.get(category, category)} : {count}")
    if analysis.errors:
        print(f"  {len(analysis.errors)} erreur(s) d'analyse, voir le rapport.")
    print(f"Rapport : {args.out / 'rapport.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
