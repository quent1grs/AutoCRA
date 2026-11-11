"""Collecteur des preuves de processus présentes dans le dépôt.

Il cherche des fichiers et des réglages de la chaîne de livraison : politique
de sécurité, contact, mises à jour automatiques des dépendances, tests,
signature des livrables, utilisateur d'exécution des conteneurs.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..model import Finding, Location, Polarity

SKIP_DIRS = {".git", ".devcontainer", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
MAX_BYTES = 400_000


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _first_line(text: str, pattern: str) -> int | None:
    regex = re.compile(pattern, re.IGNORECASE)
    for number, line in enumerate(text.splitlines(), start=1):
        if regex.search(line):
            return number
    return None


def run(target: Path, commit: str | None = None) -> list[Finding]:
    root = target.resolve()
    findings: list[Finding] = []

    def add(rule, message, path, line, reqs, polarity=Polarity.POUR, category="process"):
        findings.append(Finding(
            category=category, rule_id=rule, message=message,
            location=Location(str(path.relative_to(root)) if isinstance(path, Path) else path, line, commit=commit),
            requirements=reqs, polarity=polarity,
        ))

    seen: set[str] = set()
    startup_drops = 0
    for path in _walk(root):
        rel = path.relative_to(root)
        name = path.name.lower()
        parts = [p.lower() for p in rel.parts]

        if name == "security.md":
            text = _read(path)
            add("security-policy", "Politique de sécurité publiée dans le dépôt", path, 1, ["CRA-II-5", "CRA-II-6"])
            line = _first_line(text, r"[\w.+-]+@[\w-]+\.[\w.-]+|security/advisories|report a vulnerability")
            if line:
                add("security-contact", "Moyen de signaler une faille indiqué", path, line, ["CRA-II-6"])
            seen.add("security-policy")
        elif name == "security.txt":
            add("security-txt", "Fichier security.txt présent", path, 1, ["CRA-II-6"])
            seen.add("security-txt")
        elif name in {"dependabot.yml", "dependabot.yaml", "renovate.json", "renovate.json5", ".renovaterc"}:
            add("dependency-updates", "Mise à jour automatique des dépendances configurée", path, 1,
                ["CRA-II-2", "CRA-I-1-2a"])
            seen.add("dependency-updates")
        elif name.startswith(("changelog", "release-notes", "releasenotes")):
            add("changelog", "Notes de version tenues", path, 1, ["CRA-II-8", "CRA-II-4"])
            seen.add("changelog")
        elif re.search(r"threat[-_ ]?model|risk[-_ ]?(assessment|analysis)|analyse[-_ ]?de[-_ ]?risques", name):
            add("risk-assessment", "Document d'analyse de risques ou de modèle de menaces", path, 1, ["CRA-I-1-1"])
            seen.add("risk-assessment")
        elif ".github" in parts and "workflows" in parts and name.endswith((".yml", ".yaml")) or name == ".gitlab-ci.yml":
            text = _read(path)
            checks = [
                ("ci-tests", r"\b(pytest|npm (run )?test|pnpm test|yarn test|go test|mvn (test|verify)|cargo test|jest)\b",
                 "Tests automatiques dans la chaîne de livraison", ["CRA-II-3"]),
                ("ci-code-scanning", r"\b(codeql|semgrep|bandit|sonarqube|sonarcloud|trivy|grype|snyk|gosec|zizmor)\b",
                 "Analyse de sécurité dans la chaîne de livraison", ["CRA-II-3"]),
                ("ci-sbom", r"\bsyft\b|cyclonedx|spdx|sbom", "Inventaire des composants produit par la chaîne de livraison",
                 ["CRA-II-1"]),
                ("ci-signing", r"cosign|sigstore|attest-build-provenance|gpg --(detach-)?sign|slsa",
                 "Signature ou attestation des livrables", ["CRA-II-7", "CRA-I-1-2f"]),
            ]
            # La publication n'est ni pour ni contre : elle montre où lire la chaîne de distribution.
            line = (_first_line(text, r"docker/build-push-action|docker (buildx )?(push|imagetools create)|"
                                      r"pypa/gh-action-pypi-publish|npm publish|softprops/action-gh-release")
                    or _first_line(text, r"ghcr\.io|docker\.io|quay\.io"))
            if line:
                add("ci-publish", "Publication des livrables par la chaîne de livraison", path, line,
                    ["CRA-II-7", "CRA-II-8"], Polarity.NEUTRE)
            for rule, pattern, message, reqs in checks:
                line = _first_line(text, pattern)
                if line:
                    add(rule, message, path, line, reqs)
                    seen.add(rule)
        elif (len(parts) >= 3 and parts[-3:-1] == ["management", "commands"] and name.endswith(".py")
              and re.search(r"export|delete|purge|prune|trash|erase|anonymi", name)):
            kind = "d'export" if "export" in name else "de suppression"
            add("data-management-command", f"Commande d'administration {kind} des données", path,
                _first_line(_read(path), r"^class Command\b") or 1,
                ["CRA-I-1-2m"], Polarity.NEUTRE, "data")
        elif re.fullmatch(r"(docker-)?compose[\w.-]*\.ya?ml", name) and not re.search(r"\b(ci|test|e2e|dev)\b", name):
            lines = _read(path).splitlines()
            in_ports = False
            hardened = False
            for number, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if re.match(r"ports\s*:", stripped):
                    in_ports = True
                    continue
                if in_ports and stripped.startswith("-"):
                    add("compose-port", f"Port publié par la configuration livrée : {stripped.lstrip('- ').split('#')[0].strip().strip(chr(34))}",
                        path, number, ["CRA-I-1-2j"], Polarity.NEUTRE, "entry_point")
                    continue
                in_ports = False
                secret = re.match(r"-?\s*([A-Z0-9_]*(PASSWORD|PASSWD|SECRET|TOKEN)[A-Z0-9_]*)\s*[:=]\s*(.+)", stripped)
                if secret and not re.search(r"\$\{|^\s*$|_FILE\b", secret.group(1) + secret.group(3)):
                    add("compose-default-secret", f"Valeur de {secret.group(1)} écrite dans la configuration livrée",
                        path, number, ["CRA-I-1-2b"], Polarity.CONTRE, "setting")
                if not hardened and re.match(r"(read_only\s*:\s*true|cap_drop\s*:|security_opt\s*:|user\s*:)", stripped):
                    add("compose-hardening", "Option de durcissement du conteneur dans la configuration livrée",
                        path, number, ["CRA-I-1-2k"], category="hardening")
                    hardened = True
        elif (name in {"run", "up"} or re.fullmatch(r"(docker-)?entrypoint[\w.-]*(\.sh)?", name)) and (
                {"rootfs", "s6-rc.d", "services.d", "docker", "s6-overlay"} & set(parts) or name != "run"):
            line = _first_line(_read(path), r"^[^#]*\b(s6-setuidgid|setuidgid|gosu|su-exec|setpriv|runuser)\s+\S")
            if line and startup_drops < 12:
                add("startup-privilege-drop", "Script de démarrage qui lance le service sous un autre compte", path, line,
                    ["CRA-I-1-2k"], category="hardening")
                startup_drops += 1
        elif name == "dockerfile" or name.startswith("dockerfile."):
            text = _read(path)
            users = [(n, l) for n, l in enumerate(text.splitlines(), 1) if re.match(r"\s*USER\s+\S+", l, re.I)]
            if users and not re.match(r"\s*USER\s+(root|0)\b", users[-1][1], re.I):
                add("container-non-root", "Le conteneur s'exécute avec un utilisateur non privilégié", path,
                    users[-1][0], ["CRA-I-1-2k"], category="hardening")
            else:
                # On retient le dernier emploi : il est le plus proche du lancement du service.
                drops = [n for n, l in enumerate(text.splitlines(), 1)
                         if re.search(r"\b(s6-setuidgid|setuidgid|gosu|su-exec|setpriv|runuser)\s+\S", l)
                         and not l.lstrip().startswith("#")]
                drop = drops[-1] if drops else None
                if drop:
                    add("container-privilege-drop", "Pas d'instruction USER, mais une commande d'abandon de "
                        "privilèges est utilisée (à juger : couvre-t-elle le service principal ?)", path,
                        drop, ["CRA-I-1-2k"], Polarity.NEUTRE, "hardening")
                else:
                    add("container-root", "Aucun utilisateur non privilégié défini dans le Dockerfile "
                        "(à vérifier : un script de démarrage peut abaisser les droits)", path,
                        users[-1][0] if users else 1, ["CRA-I-1-2k"], Polarity.CONTRE, "hardening")
            line = _first_line(text, r"^\s*HEALTHCHECK\b")
            if line:
                add("container-healthcheck", "Contrôle d'état du conteneur défini", path, line, ["CRA-I-1-2h"],
                    category="hardening")

    absences = [
        ("security-policy", "Aucune politique de sécurité (SECURITY.md) trouvée dans le dépôt", ["CRA-II-5", "CRA-II-6"]),
        ("dependency-updates", "Aucune mise à jour automatique des dépendances trouvée", ["CRA-II-2"]),
        ("ci-tests", "Aucun test automatique trouvé dans la chaîne de livraison", ["CRA-II-3"]),
        ("ci-signing", "Aucune signature des livrables trouvée dans la chaîne de livraison", ["CRA-II-7"]),
        ("risk-assessment", "Aucun document d'analyse de risques trouvé dans le dépôt", ["CRA-I-1-1"]),
    ]
    for rule, message, reqs in absences:
        if rule not in seen:
            add(f"{rule}-absent", message + " (absence non prouvée : il peut exister ailleurs)", "(dépôt)", None,
                reqs, Polarity.CONTRE)
    return findings
