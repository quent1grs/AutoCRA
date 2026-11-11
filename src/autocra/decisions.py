"""Décisions humaines : qui a validé quelle fiche, quand, et sur quelle version du code.

Le journal est un fichier JSON en ajout seul. Une nouvelle décision ne remplace
pas l'ancienne : elle s'ajoute, pour garder l'historique.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .model import Status
from .requirements import BY_ID

FILENAME = "decisions.json"
# « à examiner » est l'état de départ proposé par l'outil : ce n'est pas une décision.
HUMAN_STATUSES = tuple(s for s in Status if s is not Status.A_EXAMINER)


@dataclass
class Decision:
    reference: str
    status: str
    author: str
    date: str
    commit: str | None
    note: str = ""


def load(out_dir: Path) -> list[Decision]:
    path = out_dir / FILENAME
    if not path.is_file():
        return []
    return [Decision(**item) for item in json.loads(path.read_text(encoding="utf-8"))]


def latest(out_dir: Path) -> dict[str, Decision]:
    """Dernière décision connue pour chaque exigence."""
    return {d.reference: d for d in load(out_dir)}


def record(out_dir: Path, reference: str, status: str, author: str,
           commit: str | None, note: str = "") -> Decision:
    if reference not in BY_ID:
        raise ValueError(f"Exigence inconnue : {reference}")
    if status not in {s.value for s in HUMAN_STATUSES}:
        raise ValueError(f"État inconnu : {status}. États possibles : "
                         + ", ".join(s.value for s in HUMAN_STATUSES))
    if not author.strip():
        raise ValueError("Le nom de la personne qui décide est obligatoire.")
    decision = Decision(reference, status, author.strip(),
                        datetime.now(timezone.utc).isoformat(timespec="seconds"), commit, note.strip())
    out_dir.mkdir(parents=True, exist_ok=True)
    history = load(out_dir) + [decision]
    (out_dir / FILENAME).write_text(
        json.dumps([asdict(d) for d in history], ensure_ascii=False, indent=2), encoding="utf-8")
    return decision
