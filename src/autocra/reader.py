"""Lecture par l'IA : pour une exigence, le modèle lit les extraits de code
relevés par les outils et propose une appréciation argumentée.

Règles de conception :

- Le modèle ne voit que des extraits numérotés. Toute citation qu'il rend est
  vérifiée : si le fichier ou la ligne n'était pas dans les extraits fournis,
  la citation est marquée « non vérifiée » et ne compte pas comme preuve.
- Ce qui n'a pas été montré au modèle est dit dans la fiche (« couverture »).
  Rien n'est tronqué en silence.
- Le résultat reste une proposition. Seul un humain fixe l'état d'une exigence.
- Le fournisseur de modèle est remplaçable : il suffit d'implémenter ``Reader``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .model import Evidence, Finding, Status
from .requirements import Requirement

CONTEXT_LINES = 12          # lignes montrées avant et après chaque élément
PROCESS_CONTEXT_LINES = 60  # lignes montrées après une preuve de processus (fichier entier visé)
LOW_PRIORITY_RULES = {"py-env-variable", "js-env-variable", "py-cli-argument"}
MAX_EXCERPTS = 40           # extraits par exigence
MAX_EXCERPT_CHARS = 120_000  # taille totale des extraits par exigence

STATUS_VALUES = [s.value for s in Status if s is not Status.A_EXAMINER]

ASSESSMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "etat_propose": {"type": "string", "enum": STATUS_VALUES},
        "synthese": {"type": "string"},
        "elements_pour": {"type": "array", "items": {"$ref": "#/$defs/citation"}},
        "elements_contre": {"type": "array", "items": {"$ref": "#/$defs/citation"}},
        "manques": {"type": "array", "items": {"type": "string"}},
        "confiance": {"type": "string", "enum": ["faible", "moyenne", "forte"]},
    },
    "required": ["etat_propose", "synthese", "elements_pour", "elements_contre", "manques", "confiance"],
    "additionalProperties": False,
    "$defs": {
        "citation": {
            "type": "object",
            "properties": {
                "fichier": {"type": "string"},
                "ligne": {"type": "integer"},
                "explication": {"type": "string"},
            },
            "required": ["fichier", "ligne", "explication"],
            "additionalProperties": False,
        }
    },
}

SYSTEM_PROMPT = """Tu aides un auditeur à préparer le dossier de conformité d'un logiciel au \
Cyber Resilience Act, règlement (UE) 2024/2847. On te donne une exigence de l'annexe I et des \
extraits numérotés du code du produit, relevés par des outils d'inventaire.

Ton rôle est de dire ce que ces extraits montrent pour cette exigence, pas de déclarer la conformité.

- Appuie chaque affirmation sur un extrait, en citant le fichier et le numéro de ligne tels \
qu'ils apparaissent. Ne cite jamais une ligne que tu n'as pas sous les yeux.
- Distingue ce qui va dans le sens de l'exigence et ce qui va contre.
- Les outils d'inventaire font des erreurs : écarte un élément relevé à tort et dis-le dans la synthèse.
- Choisis l'état « dépend de l'installation » quand le résultat tient à un réglage que l'exploitant \
choisit, et « absence non prouvée » quand les extraits ne permettent pas de conclure.
- Dans « manques », liste ce qu'il faudrait lire ou demander à l'éditeur pour conclure.
- Écris en français, en phrases courtes, sans parler de failles : on parle de preuves de conformité."""


@dataclass
class Citation:
    file: str
    line: int
    explanation: str
    verified: bool = True


@dataclass
class Assessment:
    """Appréciation proposée par l'IA pour une exigence."""

    reference: str
    status: Status
    summary: str
    pour: list[Citation] = field(default_factory=list)
    contre: list[Citation] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    confidence: str = "faible"
    model: str = ""
    shown: int = 0        # éléments montrés au modèle
    omitted: int = 0      # éléments non montrés, faute de place
    input_tokens: int = 0
    output_tokens: int = 0
    error: str = ""

    @property
    def unverified(self) -> int:
        return sum(not c.verified for c in self.pour + self.contre)


@dataclass
class Excerpt:
    file: str
    start: int
    end: int
    text: str
    reasons: list[str]


class Reader(Protocol):
    """Fournisseur de modèle. Reçoit un message et rend le JSON de l'appréciation."""

    name: str

    def complete(self, system: str, user: str, schema: dict) -> tuple[dict, int, int]:
        """Renvoie (appréciation, jetons en entrée, jetons en sortie)."""
        ...


# --------------------------------------------------------------------- extraits

def build_excerpts(root: Path, findings: list[Finding]) -> tuple[list[Excerpt], int]:
    """Regroupe les éléments en extraits de code numérotés. Renvoie aussi le
    nombre d'éléments laissés de côté faute de place."""
    located = [f for f in findings if f.location.line and (root / f.location.file).is_file()]
    # Les éléments défavorables et favorables passent avant l'inventaire neutre.
    # Dans l'inventaire, les réglages et arguments de commande passent en dernier :
    # ils sont nombreux et ne doivent pas chasser les routes exposées au réseau.
    order = {"contre": 0, "pour": 1, "neutre": 2}
    located.sort(key=lambda f: (order[f.polarity.value], f.rule_id in LOW_PRIORITY_RULES,
                                f.location.file, f.location.line))

    windows: dict[str, list[list]] = {}
    shown = 0
    total_chars = 0
    cache: dict[str, list[str]] = {}
    for f in located:
        lines = cache.setdefault(
            f.location.file,
            (root / f.location.file).read_text(encoding="utf-8", errors="replace").splitlines(),
        )
        start = max(1, f.location.line - CONTEXT_LINES)
        # Une preuve de processus désigne un fichier entier : on en montre davantage.
        after = PROCESS_CONTEXT_LINES if f.category == "process" or f.rule_id == "data-management-command" else CONTEXT_LINES
        end = min(len(lines), (f.location.end_line or f.location.line) + after)
        file_windows = windows.setdefault(f.location.file, [])
        merged = next((w for w in file_windows if start <= w[1] + 1 and end >= w[0] - 1), None)
        if merged:
            added = sum(len(l) + 8 for l in lines[min(start, merged[0]) - 1:max(end, merged[1])]) - merged[3]
            if total_chars + added > MAX_EXCERPT_CHARS:
                continue
            merged[0], merged[1] = min(start, merged[0]), max(end, merged[1])
            merged[2].append(f"ligne {f.location.line} : {f.message}")
            merged[3] += added
            total_chars += added
        else:
            size = sum(len(l) + 8 for l in lines[start - 1:end])
            if sum(len(w) for w in windows.values()) >= MAX_EXCERPTS or total_chars + size > MAX_EXCERPT_CHARS:
                if not file_windows:
                    del windows[f.location.file]
                continue
            file_windows.append([start, end, [f"ligne {f.location.line} : {f.message}"], size])
            total_chars += size
        shown += 1

    excerpts = []
    for file, file_windows in windows.items():
        for start, end, reasons, _ in sorted(file_windows):
            text = "\n".join(f"{n:>5}  {line}" for n, line in enumerate(cache[file][start - 1:end], start=start))
            excerpts.append(Excerpt(file, start, end, text, reasons))
    return excerpts, len(located) - shown


def build_prompt(req: Requirement, evidence: Evidence, excerpts: list[Excerpt], omitted: int) -> str:
    parts = [
        f"# Exigence {req.id}",
        f"Référence : {req.ref}",
        f"Intitulé : {req.title}",
        f"Objectif de la vérification : {req.objective}",
        "",
        "# Éléments sans emplacement dans le code",
    ]
    unlocated = [f for f in evidence.findings if not f.location.line]
    parts += [f"- ({f.polarity.value}) {f.message}" for f in unlocated] or ["Aucun."]
    parts += ["", "# Extraits de code"]
    if not excerpts:
        parts.append("Aucun extrait : les outils n'ont rien relevé pour cette exigence.")
    for e in excerpts:
        parts += [f"## {e.file}, lignes {e.start} à {e.end}", "Relevé par les outils :"]
        parts += [f"- {r}" for r in e.reasons]
        parts += ["```", e.text, "```", ""]
    if omitted:
        parts.append(f"Attention : {omitted} autre(s) élément(s) relevé(s) ne sont pas montrés ici, faute de place. "
                     "Tiens-en compte dans ta confiance et dans les manques.")
    return "\n".join(parts)


# --------------------------------------------------------------------- lecture

def assess(reader: Reader, req: Requirement, evidence: Evidence, root: Path) -> Assessment:
    excerpts, omitted = build_excerpts(root, evidence.findings)
    shown = len(evidence.findings) - omitted
    try:
        data, tokens_in, tokens_out = reader.complete(
            SYSTEM_PROMPT, build_prompt(req, evidence, excerpts, omitted), ASSESSMENT_SCHEMA)
    except Exception as exc:  # une exigence en échec ne doit pas arrêter l'analyse
        return Assessment(req.id, Status.A_EXAMINER, "", model=reader.name, shown=shown, omitted=omitted,
                          error=f"{type(exc).__name__} : {exc}")

    def citations(items) -> list[Citation]:
        return [Citation(i["fichier"], int(i["ligne"]), i["explication"],
                         verified=_is_shown(i["fichier"], int(i["ligne"]), excerpts)) for i in items]

    return Assessment(
        reference=req.id, status=Status(data["etat_propose"]), summary=data["synthese"],
        pour=citations(data["elements_pour"]), contre=citations(data["elements_contre"]),
        gaps=list(data["manques"]), confidence=data["confiance"], model=reader.name,
        shown=shown, omitted=omitted, input_tokens=tokens_in, output_tokens=tokens_out,
    )


def _is_shown(file: str, line: int, excerpts: list[Excerpt]) -> bool:
    return any(e.file == file and e.start <= line <= e.end for e in excerpts)


# --------------------------------------------------------------------- fournisseurs

class AnthropicReader:
    """Lecture par un modèle Claude, via l'API d'Anthropic."""

    def __init__(self, model: str = "claude-opus-5-5", effort: str = "high", max_tokens: int = 16000):
        try:
            import anthropic
        except ImportError as exc:
            raise RuntimeError("Le paquet anthropic est absent. Installez : pip install 'autocra[ia]'") from exc
        self._anthropic = anthropic
        self._client = anthropic.Anthropic()
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.name = model

    def complete(self, system: str, user: str, schema: dict) -> tuple[dict, int, int]:
        response = self._client.beta.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
            # Si le modèle décline une demande, l'API la rejoue sur un modèle de repli.
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        if response.stop_reason == "refusal":
            raise RuntimeError("Le modèle a décliné la demande.")
        if response.stop_reason == "max_tokens":
            raise RuntimeError("Réponse coupée : limite de longueur atteinte.")
        text = next(block.text for block in response.content if block.type == "text")
        return json.loads(text), response.usage.input_tokens, response.usage.output_tokens


def default_reader(model: str | None = None) -> Reader:
    return AnthropicReader(model=model or os.environ.get("AUTOCRA_MODEL", "claude-opus-5-5"))


class FileReader:
    """Lecture hors ligne. Écrit chaque message dans ``prompts/`` et lit la
    réponse dans ``reponses/<exigence>.json`` si elle existe.

    Sert à faire lire les extraits par n'importe quel modèle, y compris un
    modèle hébergé chez le client ou une lecture faite à la main, en gardant
    la vérification des citations.
    """

    name = "lecture hors ligne"

    def __init__(self, directory: Path):
        self.prompts = directory / "prompts"
        self.answers = directory / "reponses"
        self.prompts.mkdir(parents=True, exist_ok=True)
        self.answers.mkdir(parents=True, exist_ok=True)

    def complete(self, system: str, user: str, schema: dict) -> tuple[dict, int, int]:
        reference = user.splitlines()[0].removeprefix("# Exigence ").strip()
        (self.prompts / f"{reference}.md").write_text(
            f"{system}\n\n---\n\n{user}\n\n---\n\nRéponds en JSON selon ce schéma :\n\n"
            f"```json\n{json.dumps(schema, ensure_ascii=False, indent=2)}\n```\n", encoding="utf-8")
        answer = self.answers / f"{reference}.json"
        if not answer.exists():
            raise FileNotFoundError(f"réponse attendue dans {answer}")
        return json.loads(answer.read_text(encoding="utf-8")), 0, 0
