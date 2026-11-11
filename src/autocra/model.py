"""Modèle de données d'AutoCRA.

Trois niveaux :

- ``Finding`` : un fait brut trouvé par un outil déterministe (une route, un
  appel sortant, un réglage...). Exhaustif et reproductible.
- ``Evidence`` : une fiche de preuve pour une exigence du CRA. Elle reprend
  les six champs des critères d'évaluation des projets de normes ETSI
  EN 304 6xx (référence, objectif, préparation, activités, verdict, preuve)
  et rattache des ``Finding`` pour et contre.
- ``Status`` : les cinq états qu'un humain peut donner à une exigence.
  L'outil ne fait que proposer ; il ne déclare jamais la conformité.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Status(str, Enum):
    """Verdict sur une exigence. Seul un humain le fixe définitivement."""

    RESPECTEE = "respectée"
    PARTIELLE = "partielle"
    ECART = "écart"
    DEPEND_INSTALLATION = "dépend de l'installation"
    ABSENCE_NON_PROUVEE = "absence non prouvée"
    A_EXAMINER = "à examiner"  # état initial proposé par l'outil


class Polarity(str, Enum):
    """Sens d'un fait par rapport à l'exigence."""

    POUR = "pour"
    CONTRE = "contre"
    NEUTRE = "neutre"  # fait d'inventaire, à juger


class Source(str, Enum):
    OUTIL = "outil"
    IA = "ia"
    HUMAIN = "humain"


@dataclass(frozen=True)
class Location:
    file: str
    line: int | None = None
    end_line: int | None = None
    commit: str | None = None

    def label(self) -> str:
        if self.line is None:
            return self.file
        if self.end_line and self.end_line != self.line:
            return f"{self.file}:{self.line}-{self.end_line}"
        return f"{self.file}:{self.line}"


@dataclass
class Finding:
    """Fait brut produit par un collecteur."""

    category: str  # entry_point, outbound_call, setting, secret, crypto, update, process...
    rule_id: str
    message: str
    location: Location
    requirements: list[str]
    polarity: Polarity = Polarity.NEUTRE
    snippet: str = ""
    source: Source = Source.OUTIL
    extra: dict = field(default_factory=dict)


@dataclass
class Evidence:
    """Fiche de preuve pour une exigence, au format des critères ETSI."""

    reference: str  # identifiant de l'exigence, ex. CRA-I-1-2b
    title: str
    objective: str
    preparation: str
    activities: list[str]
    status: Status = Status.A_EXAMINER
    findings: list[Finding] = field(default_factory=list)
    questions: list[str] = field(default_factory=list)  # ce que l'éditeur doit dire
    rationale: str = ""

    @property
    def pour(self) -> list[Finding]:
        return [f for f in self.findings if f.polarity is Polarity.POUR]

    @property
    def contre(self) -> list[Finding]:
        return [f for f in self.findings if f.polarity is Polarity.CONTRE]

    @property
    def neutres(self) -> list[Finding]:
        return [f for f in self.findings if f.polarity is Polarity.NEUTRE]


def to_dict(obj) -> dict:
    """Sérialise un objet du modèle en dictionnaire JSON."""

    def convert(value):
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, list):
            return [convert(v) for v in value]
        if isinstance(value, dict):
            return {k: convert(v) for k, v in value.items()}
        return value

    return convert(asdict(obj))
