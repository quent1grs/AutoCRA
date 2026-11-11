"""Collecteur d'inventaire des composants (SBOM) avec Syft.

Syft est un outil libre (Apache 2.0) d'Anchore. Il produit un inventaire au
format CycloneDX, l'un des deux formats attendus pour le CRA.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..model import Finding, Location, Polarity


@dataclass
class SbomResult:
    available: bool
    path: Path | None = None
    components: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    error: str = ""


def run(target: Path, out_dir: Path, syft: str | None = None, timeout: int = 1800) -> SbomResult:
    exe = syft or shutil.which("syft")
    if not exe:
        return SbomResult(False, error="Syft est introuvable : l'inventaire n'a pas été produit.")
    out = out_dir / "sbom.cdx.json"
    proc = subprocess.run(
        [exe, "scan", f"dir:{target}", "-o", f"cyclonedx-json={out}", "-q"],
        capture_output=True, text=True, timeout=timeout,
        env={"SYFT_CHECK_FOR_APP_UPDATE": "false", **_base_env()},
    )
    if proc.returncode != 0 or not out.exists():
        return SbomResult(False, error=f"Syft a échoué : {proc.stderr.strip()[:500]}")
    data = json.loads(out.read_text())
    by_type: dict[str, int] = {}
    for comp in data.get("components", []):
        kind = comp.get("type", "inconnu")
        by_type[kind] = by_type.get(kind, 0) + 1
    return SbomResult(True, out, len(data.get("components", [])), by_type)


def to_findings(result: SbomResult) -> list[Finding]:
    if not result.available:
        return [Finding(
            category="sbom", rule_id="sbom-missing", message=result.error,
            location=Location(file="(analyse)"), requirements=["CRA-II-1", "CRA-I-1-2a"],
            polarity=Polarity.NEUTRE,
        )]
    return [Finding(
        category="sbom", rule_id="sbom-generated",
        message=f"Inventaire CycloneDX produit : {result.components} composants.",
        location=Location(file=result.path.name if result.path else "sbom.cdx.json"),
        requirements=["CRA-II-1", "CRA-I-1-2a"], polarity=Polarity.POUR,
        extra={"par_type": result.by_type},
    )]


def _base_env() -> dict[str, str]:
    import os
    return dict(os.environ)
