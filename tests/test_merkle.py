import pytest

from sakshi.crypto import KeyPair
from sakshi.merkle import (
    EMPTY_ROOT,
    MerkleTree,
    SignedTreeHead,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)


def naive_root(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return node_hash(naive_root(leaves[:k]), naive_root(leaves[k:]))


@pytest.fixture(scope="module")
def tree():
    t = MerkleTree()
    for i in range(40):
        t.append(f"entry-{i}".encode())
    return t


def test_empty_tree():
    assert MerkleTree().root() == EMPTY_ROOT


def test_root_matches_rfc6962_definition(tree):
    for n in range(1, 41):
        assert tree.root(n) == naive_root(tree.leaves[:n])


def test_every_inclusion_proof(tree):
    for n in range(1, 41):
        root = tree.root(n)
        for i in range(n):
            proof = tree.inclusion_proof(i, n)
            assert verify_inclusion(tree.leaves[i], i, n, proof, root)
            assert not verify_inclusion(leaf_hash(b"forged"), i, n, proof, root)
            if n > 1:
                assert not verify_inclusion(tree.leaves[i], (i + 1) % n, n, proof, root)


def test_every_consistency_proof(tree):
    for n in range(1, 41):
        for m in range(1, n + 1):
            proof = tree.consistency_proof(m, n)
            assert verify_consistency(m, n, tree.root(m), tree.root(n), proof)
            if m < n:
                assert not verify_consistency(m, n, leaf_hash(b"x"), tree.root(n), proof)


def test_rewritten_history_is_inconsistent():
    honest, forked = MerkleTree(), MerkleTree()
    for i in range(10):
        honest.append(f"e{i}".encode())
        forked.append(b"EDITED" if i == 3 else f"e{i}".encode())
    old_root = honest.root(6)
    for i in range(10, 15):
        forked.append(f"e{i}".encode())
    # the forked log can't prove it extends the head an auditor saw earlier
    assert not verify_consistency(6, 15, old_root, forked.root(15), forked.consistency_proof(6, 15))


def test_leaf_and_node_hashes_are_domain_separated():
    a, b = leaf_hash(b"a"), leaf_hash(b"b")
    assert leaf_hash(a + b) != node_hash(a, b)


def test_signed_tree_head():
    k = KeyPair.generate()
    t = MerkleTree()
    t.append(b"x")
    sth = SignedTreeHead.create("log", 1, t.root(), "k1", k.signing_private)
    assert sth.verify(k.signing_public)
    assert SignedTreeHead.from_dict(sth.to_dict()).verify(k.signing_public)
    forged = SignedTreeHead("log", 2, sth.root_hash, sth.timestamp, "k1", sth.signature)
    assert not forged.verify(k.signing_public)


def test_proof_size_is_logarithmic():
    t = MerkleTree()
    for i in range(100_000):
        t.append_leaf_hash(leaf_hash(i.to_bytes(4, "big")))
    proof = t.inclusion_proof(54_321)
    assert len(proof) <= 17
    assert verify_inclusion(t.leaves[54_321], 54_321, len(t), proof, t.root())
