#!/usr/bin/env bash
# Prépare une version à remettre à un client : construit le paquet, calcule
# ses empreintes et, si une clé est fournie, les signe.
#
#   ./scripts/publier.sh                       # paquet + empreintes
#   ./scripts/publier.sh cle-privee.pem        # paquet + empreintes signées
#
# Créer la clé de signature, une seule fois, et la garder hors du dépôt :
#   openssl genpkey -algorithm ed25519 -out cle-privee.pem
#   openssl pkey -in cle-privee.pem -pubout -out cle-publique.pem
#
# Le client vérifie avec :
#   sha256sum -c SHA256SUMS
#   openssl pkeyutl -verify -pubin -inkey cle-publique.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -n "$(git status --porcelain)" ]]; then
    echo "Le dépôt contient des changements non enregistrés : version refusée." >&2
    exit 1
fi

./scripts/verifier.sh

rm -rf dist
python -m pip wheel . --no-deps --wheel-dir dist --quiet
git rev-parse HEAD > dist/VERSION_DU_CODE

(cd dist && sha256sum -- *.whl VERSION_DU_CODE > SHA256SUMS)
echo "Empreintes écrites dans dist/SHA256SUMS"

if [[ $# -ge 1 ]]; then
    openssl pkeyutl -sign -inkey "$1" -rawin -in dist/SHA256SUMS -out dist/SHA256SUMS.sig
    echo "Signature écrite dans dist/SHA256SUMS.sig"
else
    echo "Aucune clé fournie : les empreintes ne sont pas signées."
fi
