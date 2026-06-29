#!/usr/bin/env python3
"""Map Biscuit + /contract ZK security primitives."""
from __future__ import annotations

PRIMITIVES = [
    ("semantic_byte", "8-bit emergence state — libcontract/src/semantic_byte.zig"),
    ("semantic_commitment", "commit-reveal over byte stream — libcontract/src/commit.zig"),
    ("capability", "signed RBAC ladder + zk-sealed params — capability.zig"),
    ("biscuit_policy", "Datalog attenuation over committed facts — eclipse-biscuit/biscuit"),
    ("zkproof", "Schnorr PoK discrete log — libcontract/src/zkproof.zig (identity)"),
    ("contract-deploy", "sign-before-swap deploy gate — scripts/deploy.sh"),
]

def main() -> None:
    print("Biscuit × semantic_byte ZK security (contract-native)")
    for name, desc in PRIMITIVES:
        print(f"{name}\t{desc}")


if __name__ == "__main__":
    main()