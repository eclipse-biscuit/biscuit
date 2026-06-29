#!/usr/bin/env python3
"""Build contract-deploy authorization policy artifact."""
from __future__ import annotations

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from semantic_byte_biscuit import policy_bundle, write_policy_artifact  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cells", default="1,42,6,7", help="comma-separated semantic byte values")
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "out"))
    ap.add_argument("--name", default="contract_deploy_policy")
    args = ap.parse_args()

    cells = [int(x.strip()) for x in args.cells.split(",") if x.strip()]
    bundle = policy_bundle(cells, scope="contract-deploy")
    os.makedirs(args.out_dir, exist_ok=True)
    path = os.path.join(args.out_dir, f"{args.name}.json")
    write_policy_artifact(path, bundle)
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())