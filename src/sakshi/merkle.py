"""Append-only transparency log (Merkle tree, RFC 6962 / RFC 9162 style).

This is the same structure Certificate Transparency uses to keep every TLS
certificate ever issued publicly auditable.

* Every entry is a leaf: ``leaf = SHA-256(0x00 || entry)``.
* Inner nodes: ``node = SHA-256(0x01 || left || right)``. The two prefixes
  stop an attacker passing off an inner node as a leaf (second-preimage
  attack).
* The **root hash** commits to every entry ever logged. Change one byte of
  one old entry and the root changes.

The log operator periodically signs a **Signed Tree Head** (size, root,
time). With it, anyone can check two things:

* **Inclusion proof:** "entry #42 is in the tree with this root". This takes
  O(log n) hashes, about 20 hashes for a million entries.
* **Consistency proof:** "the tree of size 1000 is a prefix of the tree of
  size 1500". Old entries were neither modified nor removed, so the log is
  append-only. An auditor that saved an old tree head can catch the operator
  rewriting history.

Why not a blockchain? We need tamper-evidence, not leaderless consensus. A
signed Merkle log gives the same evidence guarantees with no mining, no
tokens, millisecond appends and kilobyte proofs. Independent auditors that
cross-check tree heads stop the operator from silently forking the log.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .canonical import canonical_json
from .crypto import b64d, b64e, sha256, sign, verify

_STH_PREFIX = b"sakshi/tree-head/v1\n"


def leaf_hash(entry: bytes) -> bytes:
    return sha256(b"\x00" + entry)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


EMPTY_ROOT = sha256(b"")


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class MerkleTree:
    """In-memory tree over leaf hashes.

    Hashes of *complete* subtrees (power-of-two sized, aligned) never change
    once all their leaves exist, so they are cached. That makes appends,
    roots and proofs O(log n) amortised instead of O(n).
    """

    def __init__(self, leaves: list[bytes] | None = None) -> None:
        self.leaves: list[bytes] = list(leaves or [])
        self._cache: dict[tuple[int, int], bytes] = {}

    def __len__(self) -> int:
        return len(self.leaves)

    def append(self, entry: bytes) -> int:
        self.leaves.append(leaf_hash(entry))
        return len(self.leaves) - 1

    def append_leaf_hash(self, h: bytes) -> int:
        self.leaves.append(h)
        return len(self.leaves) - 1

    def _hash(self, start: int, end: int) -> bytes:
        n = end - start
        if n == 1:
            return self.leaves[start]
        complete = n & (n - 1) == 0
        if complete and (start, end) in self._cache:
            return self._cache[(start, end)]
        k = _split(n)
        h = node_hash(self._hash(start, start + k), self._hash(start + k, end))
        if complete:
            self._cache[(start, end)] = h
        return h

    def root(self, size: int | None = None) -> bytes:
        size = len(self.leaves) if size is None else size
        if not 0 <= size <= len(self.leaves):
            raise ValueError("size out of range")
        return EMPTY_ROOT if size == 0 else self._hash(0, size)

    # ------------------------------------------------------------- inclusion
    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        size = len(self.leaves) if size is None else size
        if not 0 <= index < size <= len(self.leaves):
            raise ValueError("index/size out of range")
        return self._path(index, 0, size)

    def _path(self, m: int, start: int, end: int) -> list[bytes]:
        n = end - start
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return self._path(m, start, start + k) + [self._hash(start + k, end)]
        return self._path(m - k, start + k, end) + [self._hash(start, start + k)]

    # ----------------------------------------------------------- consistency
    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[bytes]:
        new_size = len(self.leaves) if new_size is None else new_size
        if not 0 < old_size <= new_size <= len(self.leaves):
            raise ValueError("sizes out of range")
        if old_size == new_size:
            return []
        return self._subproof(old_size, 0, new_size, True)

    def _subproof(self, m: int, start: int, end: int, complete: bool) -> list[bytes]:
        n = end - start
        if m == n:
            return [] if complete else [self._hash(start, end)]
        k = _split(n)
        if m <= k:
            return self._subproof(m, start, start + k, complete) + [self._hash(start + k, end)]
        return self._subproof(m - k, start + k, end, False) + [self._hash(start, start + k)]


# ------------------------------------------------------------------ verifiers
def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2. `leaf` is the leaf *hash*."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    """RFC 9162 section 2.1.4.2."""
    if old_size == new_size:
        return old_root == new_root and not proof
    if not 0 < old_size < new_size or not proof:
        return False
    if old_size & (old_size - 1) == 0:          # old tree is a complete subtree
        proof = [old_root] + proof
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0


# ----------------------------------------------------------- signed tree head
@dataclass(frozen=True)
class SignedTreeHead:
    log_id: str
    tree_size: int
    root_hash: str          # base64
    timestamp: int
    key_id: str
    signature: str

    def _message(self) -> bytes:
        return _STH_PREFIX + canonical_json({"log_id": self.log_id, "tree_size": self.tree_size,
                                             "root_hash": self.root_hash, "timestamp": self.timestamp})

    @classmethod
    def create(cls, log_id: str, tree_size: int, root: bytes, key_id: str, private_key_b64: str,
               timestamp: int | None = None) -> SignedTreeHead:
        ts = int(time.time()) if timestamp is None else timestamp
        unsigned = cls(log_id, tree_size, b64e(root), ts, key_id, "")
        return cls(log_id, tree_size, b64e(root), ts, key_id, sign(private_key_b64, unsigned._message()))

    def verify(self, public_key_b64: str) -> bool:
        return verify(public_key_b64, self._message(), self.signature)

    @property
    def root(self) -> bytes:
        return b64d(self.root_hash)

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, d: dict) -> SignedTreeHead:
        return cls(**{k: d[k] for k in ("log_id", "tree_size", "root_hash", "timestamp", "key_id", "signature")})
