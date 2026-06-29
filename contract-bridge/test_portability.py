"""Portability tests — biscuit semantic-byte ZK bridge (no biscuit-auth wheel required)."""
import json
import os
import tempfile
import unittest

from semantic_byte_biscuit import (
    BLIND_LEN,
    SemanticByte,
    attenuation_block,
    commit,
    commit_semantic_stream,
    deploy_authorization_policy,
    operator_collapse_at_42,
    policy_bundle,
    semantic_facts,
    verify_commitment,
    witness_pair,
    write_policy_artifact,
)


class TestSemanticByteBiscuit(unittest.TestCase):
    def test_seal_bit_on_42(self):
        sb = SemanticByte(42)
        self.assertTrue(sb.seal_bit)
        self.assertEqual(sb.hebrew(), "ש")

    def test_witness_and_collapse(self):
        self.assertEqual(witness_pair(1, 1), 2)
        self.assertEqual(operator_collapse_at_42(6, 7), 42)

    def test_commit_round_trip(self):
        val = b"semantic-byte-stream"
        blind = bytes(range(BLIND_LEN))
        c = commit(val, blind)
        self.assertTrue(verify_commitment(c, val, blind))
        self.assertFalse(verify_commitment(c, b"tampered", blind))

    def test_stream_commitment(self):
        cells = [1, 2, 42, 255]
        sealed = commit_semantic_stream(cells)
        self.assertEqual(sealed["length"], 4)
        payload = bytes(cells)
        blind = bytes.fromhex(sealed["blinding"])
        c = bytes.fromhex(sealed["commitment"])
        self.assertTrue(verify_commitment(c, payload, blind))

    def test_facts_include_seal(self):
        facts = semantic_facts([42, 10])
        self.assertTrue(any("semantic_byte(0, 42)" in f for f in facts))
        self.assertTrue(any("semantic_seal(0)" in f for f in facts))

    def test_deploy_policy_mentions_commitment(self):
        sealed = commit_semantic_stream([6, 7, 42])
        pol = deploy_authorization_policy(commitment_hex=sealed["commitment"])
        self.assertIn("semantic_commitment", pol)
        self.assertIn("contract-deploy", pol)

    def test_attenuation_rejects_escalation(self):
        with self.assertRaises(ValueError):
            attenuation_block(42, 100)

    def test_policy_bundle_writes(self):
        bundle = policy_bundle([1, 42, 6, 7])
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "deploy-policy.json")
            write_policy_artifact(path, bundle)
            loaded = json.load(open(path, encoding="utf-8"))
            self.assertIn("policy", loaded)
            self.assertIn("sealed", loaded)


if __name__ == "__main__":
    unittest.main()