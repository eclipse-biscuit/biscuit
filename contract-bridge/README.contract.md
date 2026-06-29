# Biscuit × semantic_byte ZK security (contract-native)

[Eclipse Biscuit](https://github.com/eclipse-biscuit/biscuit) provides **attenuated
authorization** (Datalog policies on signed tokens). `/contract` provides:

| Layer | Module | Role |
|-------|--------|------|
| State | `semantic_byte.zig` | 8-bit emergence per cell; seal bit (b5) |
| Hiding | `commit.zig` | commit-reveal over byte streams (honest wall: NOT SNARK) |
| RBAC | `capability.zig` | signed capability ladder + zk-sealed params |
| Identity | `zkproof.zig` | Schnorr PoK of discrete log |
| Deploy | `scripts/deploy.sh` | sign-before-swap wallet gate |

**Security composition:** semantic bytes define *what* is sealed; commitments hide the
stream until open; Biscuit policies define *who* may deploy/attenuate; `contract-deploy`
enforces the live binary swap under witness.

## Gates

```bash
bash scripts/gate.sh
bash ../../../witness/biscuit_semantic_byte_gate.sh
```

## Build deploy policy artifact

```bash
python3 scripts/build_deploy_policy.py --cells 1,42,6,7
bash ../../../scripts/deploy-biscuit-policy.sh --policy references/upstream/biscuit/out/contract_deploy_policy.json
```

## Wallet deploy witness

```bash
bash ../../../scripts/deploy.sh --witness 'bash witness/biscuit_semantic_byte_gate.sh'
```