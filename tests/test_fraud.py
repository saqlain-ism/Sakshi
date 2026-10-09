import zlib

from fraud_benchmark import evaluate, generate

from sakshi.fraud import detect_collusion, find_rings
from sakshi.orders import OrderView


def test_benchmark_held_out_seed():
    r = evaluate(seed=42)
    assert r["precision"] >= 0.9
    assert r["recall"] >= 0.9
    assert r["per_type"]["honest"]["flagged"] == 0


def test_loyal_local_shops_are_not_flagged():
    orders, labels = generate(seed=7)
    flagged = {r.seller_id for r in detect_collusion(orders=orders) if r.flagged}
    assert not {s for s in flagged if labels[s] == "loyal_local"}


def test_rings_are_reported_together():
    orders, labels = generate(seed=5)
    risks = {r.seller_id: r for r in detect_collusion(orders=orders)}
    ring = sorted(s for s, lbl in labels.items() if lbl == "ring" and s.startswith("fraud-ring0"))
    assert all(risks[s].flagged for s in ring)
    assert set(risks[ring[0]].ring) == set(ring[1:])


def test_find_rings_needs_heavy_overlap():
    rings = find_rings({"a": {"x", "y", "z", "w"}, "b": {"x", "y", "z", "v"}, "c": {"q"}})
    assert rings["a"] == ["b"] and "c" not in rings


def _orders(seller, buyers, n_each, delivery_fraction, start=0):
    out = []
    for b in buyers:
        for k in range(n_each):
            t = start + 1000 * k + zlib.crc32(f"{seller}{b}".encode()) % 500
            out.append(OrderView(f"{seller}-{b}-{k}", seller, "bpp", "bap", b, t, 10000, t + 1000, 0,
                                 delivered_at=t + int(1000 * delivery_fraction)))
    return out


def test_small_network_uses_the_physical_sanity_rule():
    """With only a few sellers, flags need captive buyers AND impossible delivery speed."""
    shoppers = [f"s{i}" for i in range(12)]
    orders = []
    for i, seller in enumerate(["a", "b", "c"]):
        orders += _orders(seller, shoppers[i * 4:(i + 1) * 4] + shoppers[((i + 1) % 3) * 4:((i + 1) % 3) * 4 + 2], 2, 0.5)
    orders += _orders("loyal", ["r1", "r2", "r3"], 3, 0.5)            # loyal regulars, normal delivery
    orders += _orders("booster", ["p1", "p2", "p3"], 4, 0.02)         # puppets, instant "delivery"
    flagged = {r.seller_id for r in detect_collusion(orders=orders) if r.flagged}
    assert flagged == {"booster"}
