"""Biscuit × contract semantic_byte ZK security bridge.

Layers (native to /contract):
  1. semantic_byte.zig — 8-bit emergence state per cell (seal bit b5)
  2. commit.zig — hiding+binding commitment over byte streams (NOT SNARK; honest wall)
  3. capability.zig — signed RBAC ladder with zk-sealed params
  4. biscuit Datalog — attenuated authorization policies over committed facts

Biscuit proves *who may act*; semantic bytes prove *what state is sealed*;
commit proves *the stream is fixed* without revealing it until open.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass

HEBREW = "אבגדהוזחטיכלמנסעפצקרשת"
COMMIT_DOMAIN = b"aiko-commit-v1"
BLIND_LEN = 32


@dataclass(frozen=True)
class SemanticByte:
    value: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= 255:
            raise ValueError(f"out of range: {self.value}")

    @property
    def seal_bit(self) -> bool:
        return bool(self.value & 32)

    def hebrew(self) -> str:
        return HEBREW[self.value % 22]

    def biscuit_fact(self, index: int) -> str:
        return f"semantic_byte({index}, {self.value});"

    def biscuit_seal_fact(self, index: int) -> str:
        return f"semantic_seal({index});" if self.seal_bit else ""


def witness_pair(a: int, b: int) -> int:
    return 2 if a == 1 and b == 1 else (a * b) & 0xFF


def operator_collapse_at_42(a: int, b: int) -> int:
    if (a, b) in ((6, 7), (7, 6)):
        return 42
    mul = (a * b) & 0xFF
    add = (a + b) & 0xFF
    xor = a ^ b
    if mul in (add, xor) or add == xor:
        return 42
    return mul


def commit(value: bytes, blinding: bytes) -> bytes:
    if len(blinding) != BLIND_LEN:
        raise ValueError("blinding must be 32 bytes")
    h = hashlib.sha256()
    h.update(COMMIT_DOMAIN)
    h.update(blinding)
    h.update(value)
    return h.digest()


def verify_commitment(commitment: bytes, value: bytes, blinding: bytes) -> bool:
    return commit(value, blinding) == commitment


def commit_semantic_stream(cells: list[int]) -> dict:
    """ZK-seal a semantic-byte stream (commit-reveal; mirrors commit.zig)."""
    payload = bytes(c & 0xFF for c in cells)
    blinding = secrets.token_bytes(BLIND_LEN)
    c = commit(payload, blinding)
    return {
        "commitment": c.hex(),
        "blinding": blinding.hex(),
        "length": len(cells),
        "domain": COMMIT_DOMAIN.decode(),
    }


def semantic_facts(cells: list[int]) -> list[str]:
    facts: list[str] = []
    for i, v in enumerate(cells):
        sb = SemanticByte(v)
        facts.append(sb.biscuit_fact(i))
        sf = sb.biscuit_seal_fact(i)
        if sf:
            facts.append(sf)
    return facts


def deploy_authorization_policy(
    *,
    commitment_hex: str,
    max_byte: int = 42,
    scope: str = "contract-deploy",
    role: str = "operator",
) -> str:
    """Datalog-shaped policy for /contract-deploy attenuation."""
    lines = [
        f'right("{scope}", "{role}");',
        f'semantic_commitment("{commitment_hex}");',
        "check if semantic_byte($i, $b), $b <= " + str(max_byte) + ";",
        "check if semantic_seal($i);",
        f'allow if right("{scope}", "{role}"), semantic_commitment("{commitment_hex}");',
    ]
    return "\n".join(lines)


def attenuation_block(parent_max: int, child_max: int) -> str:
    """Biscuit attenuation: child token cannot exceed parent byte ceiling."""
    if child_max > parent_max:
        raise ValueError("attenuation violation: child exceeds parent")
    return "\n".join(
        [
            f"check if semantic_byte($i, $b), $b <= {child_max};",
            f"// attenuated from parent max {parent_max}",
        ]
    )


def policy_bundle(cells: list[int], scope: str = "contract-deploy") -> dict:
    sealed = commit_semantic_stream(cells)
    policy = deploy_authorization_policy(
        commitment_hex=sealed["commitment"],
        max_byte=max(cells) if cells else 255,
        scope=scope,
    )
    return {
        "sealed": sealed,
        "facts": semantic_facts(cells),
        "policy": policy,
        "attenuation": attenuation_block(max(cells) if cells else 255, 42),
    }


def write_policy_artifact(path: str, bundle: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)