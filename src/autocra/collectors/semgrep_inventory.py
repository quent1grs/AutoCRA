"""Collecteur Semgrep : exécute les règles d'inventaire d'AutoCRA.

Semgrep tourne en local, sans compte ni envoi de données (métriques
désactivées). Le code du client ne quitte pas sa machine.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from importlib import resources
from pathlib import Path

from ..model import Finding, Location, Polarity

# Dossiers qui ne font pas partie du produit livré.
DEFAULT_EXCLUDES = (
    "node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__",
    "tests", "test", "docs", "migrations", "fixtures", ".devcontainer",
    "*.spec.ts", "*.spec.js", "*.test.ts", "*.test.js", "*.test.tsx", "test_*.py", "conftest.py",
)


def rules_dir() -> Path:
    return Path(str(resources.files("autocra") / "rules"))


def semgrep_executable() -> str:
    found = shutil.which("semgrep")
    if found:
        return found
    candidate = Path(sys.executable).parent / "semgrep"
    if candidate.exists():
        return str(candidate)
    raise RuntimeError("Semgrep est introuvable. Installez-le avec : pip install semgrep")


def run(target: Path, commit: str | None = None, excludes: tuple[str, ...] = DEFAULT_EXCLUDES,
        timeout: int = 1800) -> tuple[list[Finding], list[str]]:
    """Exécute Semgrep et renvoie les faits trouvés et les erreurs éventuelles."""
    cmd = [
        semgrep_executable(), "scan",
        "--config", str(rules_dir()),
        "--json", "--quiet",
        "--metrics=off", "--disable-version-check",
        "--no-git-ignore",
        "--timeout", "30",
    ]
    for pattern in excludes:
        cmd += ["--exclude", pattern]
    cmd.append(str(target))

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if not proc.stdout.strip():
        raise RuntimeError(f"Semgrep n'a rien renvoyé : {proc.stderr.strip()[:500]}")
    data = json.loads(proc.stdout)
    return parse(data, target, commit), [e.get("message", str(e)) for e in data.get("errors", [])]


def parse(data: dict, target: Path, commit: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    root = target.resolve()
    for result in data.get("results", []):
        meta = result.get("extra", {}).get("metadata", {})
        path = Path(result["path"])
        try:
            rel = str(path.resolve().relative_to(root))
        except ValueError:
            rel = result["path"]
        findings.append(Finding(
            category=meta.get("autocra-category", "autre"),
            rule_id=result["check_id"].split(".")[-1],
            message=result.get("extra", {}).get("message", ""),
            location=Location(
                file=rel,
                line=result["start"]["line"],
                end_line=result["end"]["line"],
                commit=commit,
            ),
            requirements=list(meta.get("autocra-requirements", [])),
            polarity=Polarity(meta.get("autocra-polarity", "neutre")),
            snippet=_snippet(root / rel, result["start"]["line"], result["end"]["line"]),
            extra={"note": meta["autocra-note"]} if "autocra-note" in meta else {},
        ))
    findings.sort(key=lambda f: (f.location.file, f.location.line or 0, f.rule_id))
    return findings


def _snippet(path: Path, start: int, end: int, max_lines: int = 4) -> str:
    """Lit les lignes du résultat dans le fichier (Semgrep OSS ne les renvoie plus)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    stop = min(end, start + max_lines - 1)
    return "\n".join(lines[start - 1:stop]).strip()
