#!/usr/bin/env bash
# Runnable gate: biscuit semantic-byte ZK bridge (Python + native zig ground truth).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3}"
CONTRACT_ROOT="$(cd "$ROOT/../../.." && pwd)"

"$PY" -m unittest test_portability -v
PYTHONPATH="$ROOT" "$PY" scripts/list_security_primitives.py | grep -q semantic_commitment

echo "== libcontract semantic_byte.zig =="
(cd "$CONTRACT_ROOT/libcontract" && zig test src/semantic_byte.zig --test-filter 'SemanticByte' >/dev/null)

echo "== libcontract commit.zig (zk commitment) =="
(cd "$CONTRACT_ROOT/libcontract" && zig test src/commit.zig >/dev/null)

echo "== libcontract capability.zig (RBAC ladder) =="
(cd "$CONTRACT_ROOT/libcontract" && zig test src/capability.zig >/dev/null)

if "$PY" -c "import biscuit_auth" 2>/dev/null; then
  echo "== optional: biscuit-auth python present =="
  "$PY" -c "import biscuit_auth; print('biscuit_auth', biscuit_auth.__name__)"
else
  echo "skip: biscuit-auth wheel (policy DSL + zig gates are sufficient)"
fi

echo "GATE GREEN: biscuit semantic-byte zk security"