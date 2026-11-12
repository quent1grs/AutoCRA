"""Assemble les faits des collecteurs en fiches de preuve par exigence."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import decisions as decisions_module
from . import reader as reader_module
from . import requirements
from .collectors import repo_files, sbom, semgrep_inventory
from .model import Evidence, Finding, Polarity, Status


@dataclass
class Analysis:
    target: str
    commit: str | None
    generated_at: str
    evidences: list[Evidence]
    findings: list[Finding]
    sbom: sbom.SbomResult
    errors: list[str] = field(default_factory=list)
    assessments: dict[str, reader_module.Assessment] = field(default_factory=dict)
    decisions: dict = field(default_factory=dict)  # dernière décision humaine par exigence
    second_assessments: dict[str, reader_module.Assessment] = field(default_factory=dict)  # contre-lecture

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.category] = out.get(f.category, 0) + 1
        return out


def git_commit(target: Path) -> str | None:
    try:
        proc = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() or None if proc.returncode == 0 else None


def propose_status(evidence: Evidence) -> tuple[Status, str]:
    """Propose un état de départ. Ce n'est jamais un verdict de conformité."""
    pour, contre, neutres = len(evidence.pour), len(evidence.contre), len(evidence.neutres)
    if not evidence.findings:
        return Status.ABSENCE_NON_PROUVEE, "Aucun élément trouvé par les outils. À compléter par l'éditeur ou par lecture."
    if contre and not pour:
        return Status.A_EXAMINER, f"{contre} élément(s) défavorable(s), aucun élément favorable trouvé."
    if contre:
        return Status.A_EXAMINER, f"{pour} élément(s) favorable(s) et {contre} défavorable(s) : à arbitrer."
    if pour:
        return Status.A_EXAMINER, f"{pour} élément(s) favorable(s), aucun défavorable trouvé. Couverture à confirmer."
    return Status.A_EXAMINER, f"{neutres} élément(s) d'inventaire à juger."


def analyse(target: Path, out_dir: Path, syft: str | None = None, with_sbom: bool = True,
            excludes: tuple[str, ...] | None = None,
            reader: reader_module.Reader | None = None,
            only: tuple[str, ...] | None = None,
            second_reader: reader_module.Reader | None = None) -> Analysis:
    target = target.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    commit = git_commit(target)
    errors: list[str] = []

    findings, semgrep_errors = semgrep_inventory.run(
        target, commit, semgrep_inventory.DEFAULT_EXCLUDES if excludes is None else excludes)
    errors += semgrep_errors
    findings += repo_files.run(target, commit)
    sbom_result = sbom.run(target, out_dir, syft) if with_sbom else sbom.SbomResult(False, error="Inventaire non demandé.")
    findings += sbom.to_findings(sbom_result)

    evidences: list[Evidence] = []
    for req in requirements.REQUIREMENTS:
        evidence = Evidence(
            reference=req.id, title=req.title, objective=req.objective,
            preparation=req.preparation, activities=list(req.activities),
            questions=list(req.questions),
            findings=[f for f in findings if req.id in f.requirements],
        )
        evidence.status, evidence.rationale = propose_status(evidence)
        evidences.append(evidence)

    assessments: dict[str, reader_module.Assessment] = {}
    second_assessments: dict[str, reader_module.Assessment] = {}
    for current, results in ((reader, assessments), (second_reader, second_assessments)):
        if current is None:
            continue
        for req, evidence in zip(requirements.REQUIREMENTS, evidences):
            if only and req.id not in only:
                continue
            assessment = reader_module.assess(current, req, evidence, target)
            # Une contre-lecture peut ne porter que sur quelques exigences : les autres sont ignorées.
            if current is second_reader and assessment.error.startswith("MissingAnswer"):
                continue
            results[req.id] = assessment

    return Analysis(
        assessments=assessments, second_assessments=second_assessments, decisions=decisions_module.latest(out_dir),
        target=str(target), commit=commit,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        evidences=evidences, findings=findings, sbom=sbom_result, errors=errors,
    )


__all__ = ["Analysis", "analyse", "propose_status", "Polarity"]
