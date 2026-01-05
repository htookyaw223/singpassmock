#!/usr/bin/env bash
set -euo pipefail

# Generate a Singpass OIDC v2 client_assertion JWT using the bundled RP key.
# Usage (env overrides):
#   CLIENT_ID=my-mock-client
#   AUD=http://localhost:5156/singpass/v2
#   KEY_PATH=./static/certs/oidc-v2-rp-secret.json

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

CLIENT_ID="${CLIENT_ID:-my-mock-client}"
AUD="${AUD:-http://localhost:5156/singpass/v2}"
KEY_PATH="${KEY_PATH:-static/certs/oidc-v2-rp-secret.json}"

if [ ! -f "$KEY_PATH" ]; then
  echo "Key file not found: $KEY_PATH" >&2
  exit 1
fi

node - "$CLIENT_ID" "$AUD" "$KEY_PATH" <<'NODE'
const { SignJWT, importJWK } = require('jose')
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const [clientId, aud, keyPath] = process.argv.slice(2)
const jwk = JSON.parse(fs.readFileSync(path.resolve(keyPath))).keys[0]

const alg =
  jwk.alg ||
  (jwk.kty === 'EC' && jwk.crv === 'P-256'
    ? 'ES256'
    : jwk.kty === 'EC' && jwk.crv === 'P-384'
      ? 'ES384'
      : jwk.kty === 'EC' && jwk.crv === 'P-521'
        ? 'ES512'
        : 'RS256')

;(async () => {
  const key = await importJWK(jwk, alg)
  const jwt = await new SignJWT({
    iss: clientId,
    sub: clientId,
    aud,
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({ alg, kid: jwk.kid, typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime('52m')
    .sign(key)

  console.log(jwt)
})()
NODE
