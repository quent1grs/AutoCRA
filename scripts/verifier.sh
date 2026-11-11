#!/usr/bin/env bash
# Vérification à lancer avant chaque envoi de code, tant que les tests ne
# tournent pas sur GitHub : les tests, puis AutoCRA appliqué à lui-même.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Tests =="
python -m pytest -q

echo "== AutoCRA sur lui-même =="
out="$(mktemp -d)"
python -m autocra.cli scan . -o "$out" --no-sbom
echo "Rapport : $out/rapport.md"
