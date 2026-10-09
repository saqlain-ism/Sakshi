"""Performance of the core operations (single CPU core, pure Python + OpenSSL).

    python benchmarks/perf_benchmark.py [--json out.json]

Measures what each participant pays per message:
  * signing and verifying a request header (BLAKE2b-512 + Ed25519)
  * verifying a countersigned receipt (two Ed25519 verifications)
  * appending to the Merkle log, and producing/verifying an inclusion proof
    in a log of 1,000,000 entries
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sakshi.auth import KeyRecord, create_authorization_header, verify_authorization  # noqa: E402
from sakshi.client import StaticResolver  # noqa: E402
from sakshi.crypto import KeyPair  # noqa: E402
from sakshi.merkle import MerkleTree, verify_inclusion  # noqa: E402
from sakshi.receipts import new_receipt, verify_receipt  # noqa: E402
from sakshi.replay import MemoryReplayStore  # noqa: E402


def rate(n: int, seconds: float) -> int:
    return int(n / seconds)


def timed(fn, n: int) -> float:
    t0 = time.perf_counter()
    for i in range(n):
        fn(i)
    return time.perf_counter() - t0


async def main(json_out: str | None) -> None:
    buyer, seller = KeyPair.generate(), KeyPair.generate()
    now = time.time()
    resolver = StaticResolver([KeyRecord("buyer", "k1", buyer.signing_public, now - 60, now + 3600),
                               KeyRecord("seller", "k1", seller.signing_public, now - 60, now + 3600)])
    body = json.dumps({"context": {"action": "select", "bap_id": "buyer", "transaction_id": "x" * 36},
                       "message": {"order": {"items": [{"id": f"item-{i}", "quantity": {"count": 2}}
                                                       for i in range(10)]}}}).encode()
    results: dict = {"python": platform.python_version(), "machine": platform.machine(), "body_bytes": len(body)}

    n = 5000
    headers = [create_authorization_header(body + str(i).encode(), "buyer", "k1", buyer.signing_private)
               for i in range(n)]
    results["sign_per_s"] = rate(n, timed(lambda i: create_authorization_header(body, "buyer", "k1", buyer.signing_private), n))

    store = MemoryReplayStore()
    lat = []
    t0 = time.perf_counter()
    for i in range(n):
        s = time.perf_counter()
        await verify_authorization(headers[i], body + str(i).encode(), resolver, store)
        lat.append((time.perf_counter() - s) * 1000)
    results["verify_per_s"] = rate(n, time.perf_counter() - t0)
    results["verify_ms_p50"] = round(statistics.median(lat), 3)
    results["verify_ms_p99"] = round(sorted(lat)[int(n * 0.99)], 3)

    receipts = []
    for i in range(1000):
        r = new_receipt("ORDER_CONTRACT", "seller", "buyer", "t", f"o{i}", "shop", "b",
                        {"price": {"currency": "INR", "value": "499.00"}, "promised_delivery_by": int(now) + 600})
        receipts.append(r.sign_as_issuer("k1", seller.signing_private).countersign("k1", buyer.signing_private))
    t0 = time.perf_counter()
    for r in receipts:
        await verify_receipt(r, resolver)
    results["receipt_verify_per_s"] = rate(len(receipts), time.perf_counter() - t0)

    size = 1_000_000
    tree = MerkleTree()
    t0 = time.perf_counter()
    for i in range(size):
        tree.append(i.to_bytes(8, "big"))
    results["log_append_per_s"] = rate(size, time.perf_counter() - t0)
    t0 = time.perf_counter()
    root = tree.root()
    results["root_first_s"] = round(time.perf_counter() - t0, 2)
    tree.append(b"one more")
    t0 = time.perf_counter()
    tree.root()
    results["root_after_append_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    root = tree.root()
    idx = [(i * 7919) % len(tree) for i in range(1000)]
    t0 = time.perf_counter()
    proofs = [tree.inclusion_proof(i) for i in idx]
    results["proof_gen_ms"] = round((time.perf_counter() - t0) * 1000 / len(idx), 3)
    t0 = time.perf_counter()
    ok = all(verify_inclusion(tree.leaves[i], i, len(tree), p, root) for i, p in zip(idx, proofs, strict=True))
    results["proof_verify_ms"] = round((time.perf_counter() - t0) * 1000 / len(idx), 4)
    results["proof_hashes_at_1M"] = len(proofs[0])
    results["proof_bytes_at_1M"] = 32 * len(proofs[0])
    assert ok

    print(json.dumps(results, indent=2))
    if json_out:
        Path(json_out).write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    asyncio.run(main(ap.parse_args().json))
