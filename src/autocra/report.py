"""Exports : JSON complet et rapport Markdown lisible."""

from __future__ import annotations

import json
from pathlib import Path

from .engine import Analysis
from .model import Evidence, Finding, to_dict
from .requirements import BY_ID

MAX_LISTED = 15

CATEGORY_LABELS = {
    "entry_point": "Points d'entrée",
    "outbound_call": "Appels sortants",
    "access": "Droits d'accès",
    "setting": "Réglages",
    "secret": "Secrets en dur",
    "crypto": "Cryptographie",
    "logging": "Journalisation",
    "data": "Suppression et export",
    "update": "Mises à jour",
    "process": "Preuves de processus",
    "hardening": "Durcissement",
    "sbom": "Inventaire",
}


def write_json(analysis: Analysis, path: Path) -> None:
    payload = {
        "outil": "autocra",
        "cible": analysis.target,
        "commit": analysis.commit,
        "date": analysis.generated_at,
        "avertissement": "Preuves proposées par un outil. Aucun verdict de conformité.",
        "compte_par_categorie": analysis.counts(),
        "inventaire": {
            "disponible": analysis.sbom.available,
            "composants": analysis.sbom.components,
            "erreur": analysis.sbom.error,
        },
        "erreurs": analysis.errors,
        "exigences": [to_dict(e) for e in analysis.evidences],
        "lecture_ia": {ref: to_dict(a) for ref, a in analysis.assessments.items()},
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _finding_line(f: Finding) -> str:
    snippet = f.snippet.splitlines()[0].strip() if f.snippet else ""
    if len(snippet) > 110:
        snippet = snippet[:107] + "..."
    code = f" : `{snippet}`" if snippet else ""
    note = f" ({f.extra['note']})" if f.extra.get("note") else ""
    return f"- `{f.location.label()}` {f.message}{code}{note}"


def _group(title: str, items: list[Finding]) -> list[str]:
    if not items:
        return []
    lines = [f"**{title} ({len(items)})**", ""]
    lines += [_finding_line(f) for f in items[:MAX_LISTED]]
    if len(items) > MAX_LISTED:
        lines.append(f"- et {len(items) - MAX_LISTED} autres, dans le fichier JSON.")
    lines.append("")
    return lines


def _assessment_lines(a) -> list[str]:
    if a.error:
        return [f"**Lecture par l'IA :** échec ({a.error}).", ""]
    lines = [
        f"**Lecture par l'IA ({a.model}), à valider par une personne**",
        "",
        f"- **État proposé :** {a.status.value} (confiance {a.confidence})",
        f"- **Synthèse :** {a.summary}",
        f"- **Couverture :** {a.shown} élément(s) montré(s) au modèle, {a.omitted} non montré(s).",
    ]
    if a.unverified:
        lines.append(f"- **Attention :** {a.unverified} citation(s) hors des extraits fournis, écartée(s) des preuves.")
    lines.append("")
    for title, items in (("Pour", a.pour), ("Contre", a.contre)):
        if items:
            lines += [f"*{title}*", ""]
            lines += [f"- `{c.file}:{c.line}` {c.explanation}" + ("" if c.verified else " **(non vérifiée)**")
                      for c in items]
            lines.append("")
    if a.gaps:
        lines += ["*Ce qu'il reste à lire ou à demander*", ""] + [f"- {g}" for g in a.gaps] + [""]
    return lines


def _evidence_section(e: Evidence, assessment=None) -> list[str]:
    req = BY_ID[e.reference]
    lines = [
        f"### {e.reference} : {e.title}",
        "",
        f"- **Référence :** {req.ref}",
        f"- **Objectif :** {e.objective}",
        f"- **Préparation :** {e.preparation}",
        f"- **Activités :** {' '.join(e.activities)}",
        f"- **État proposé :** {e.status.value}. {e.rationale}",
        "",
    ]
    if assessment is not None:
        lines += _assessment_lines(assessment)
    lines += _group("Éléments favorables", e.pour)
    lines += _group("Éléments défavorables", e.contre)
    lines += _group("Éléments d'inventaire à juger", e.neutres)
    if e.questions:
        lines += ["**Questions pour l'éditeur**", ""] + [f"- {q}" for q in e.questions] + [""]
    return lines


def render_markdown(analysis: Analysis) -> str:
    counts = analysis.counts()
    lines = [
        "# Rapport AutoCRA",
        "",
        f"- **Cible :** `{analysis.target}`",
        f"- **Version du code :** `{analysis.commit or 'inconnue'}`",
        f"- **Date :** {analysis.generated_at}",
        "",
        "> Ce rapport réunit des preuves localisées pour chaque exigence de l'annexe I du "
        "règlement (UE) 2024/2847. Il ne déclare pas la conformité : chaque état est une "
        "proposition à valider par une personne. Une absence de résultat ne prouve pas une absence dans le produit.",
        "",
        "## Vue d'ensemble",
        "",
        "| Catégorie | Éléments trouvés |",
        "|---|---|",
    ]
    for key, label in CATEGORY_LABELS.items():
        if key in counts:
            lines.append(f"| {label} | {counts[key]} |")
    lines.append("")
    if analysis.sbom.available:
        lines.append(f"Inventaire des composants : {analysis.sbom.components} composants (fichier `sbom.cdx.json`).")
    else:
        lines.append(f"Inventaire des composants : non produit. {analysis.sbom.error}")
    lines += ["", "| Exigence | Intitulé | Pour | Contre | À juger |", "|---|---|---|---|---|"]
    for e in analysis.evidences:
        lines.append(f"| {e.reference} | {e.title} | {len(e.pour)} | {len(e.contre)} | {len(e.neutres)} |")
    lines.append("")
    if analysis.assessments:
        tokens_in = sum(a.input_tokens for a in analysis.assessments.values())
        tokens_out = sum(a.output_tokens for a in analysis.assessments.values())
        lines += [f"Lecture par l'IA : {len(analysis.assessments)} exigence(s), "
                  f"{tokens_in} jetons lus, {tokens_out} jetons écrits.", ""]
    if analysis.errors:
        lines += ["## Erreurs d'analyse", ""] + [f"- {err[:300]}" for err in analysis.errors[:20]] + [""]
    lines += ["## Partie I : exigences sur le produit", ""]
    for e in analysis.evidences:
        if BY_ID[e.reference].part == "I":
            lines += _evidence_section(e, analysis.assessments.get(e.reference))
    lines += ["## Partie II : gestion des failles", ""]
    for e in analysis.evidences:
        if BY_ID[e.reference].part == "II":
            lines += _evidence_section(e, analysis.assessments.get(e.reference))
    return "\n".join(lines)


def write_markdown(analysis: Analysis, path: Path) -> None:
    path.write_text(render_markdown(analysis), encoding="utf-8")


def render_questionnaire(analysis: Analysis) -> str:
    """Questions que seul l'éditeur peut trancher, avec ce que l'outil a déjà trouvé."""
    lines = [
        "# Questionnaire pour l'éditeur",
        "",
        f"Version du code analysée : `{analysis.commit or 'inconnue'}`.",
        "",
        "Le code ne répond pas à ces questions. Chaque réponse devient une preuve "
        "déclarative dans le dossier : indiquez qui répond, à quelle date, et le "
        "document qui l'appuie s'il existe.",
        "",
    ]
    for e in analysis.evidences:
        if not e.questions:
            continue
        lines += [f"## {e.reference} : {e.title}", ""]
        lines.append(f"Ce que l'outil a trouvé : {len(e.pour)} élément(s) favorable(s), "
                     f"{len(e.contre)} défavorable(s), {len(e.neutres)} à juger.")
        lines.append("")
        for question in e.questions:
            lines += [f"- [ ] {question}", "  - Réponse :", "  - Document à l'appui :"]
        lines.append("")
    return "\n".join(lines)


def write_questionnaire(analysis: Analysis, path: Path) -> None:
    path.write_text(render_questionnaire(analysis), encoding="utf-8")
