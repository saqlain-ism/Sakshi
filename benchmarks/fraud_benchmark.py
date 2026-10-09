"""Synthetic marketplace benchmark for collusion detection.

Generates a month of marketplace activity with known ground truth and
measures the detector's precision and recall. The data is synthetic (there
is no public labelled ONDC fraud dataset), so these numbers show the method
works on the modelled attacks. They don't predict real-world performance.

Modelled populations:
  honest          - normal sellers of varying size, price level and speed
  loyal_local     - HARD NEGATIVES: honest neighbourhood shops whose regular
                    customers buy nowhere else (they look like Sybil islands)
  new             - honest sellers with very few orders
  sybil           - fraud: fake buyers that order only from this seller
  ring            - fraud: 2-3 sellers boosting each other with shared fake buyers
  camouflaged     - fraud: fake buyers also make one decoy order at an honest
                    seller, so they join the main graph
  adaptive        - fraud by an attacker who knows the detector: fake orders are
                    spread over the month with realistic prices and delivery
                    times. Only the graph signal remains, so this is expected
                    to be MISSED, and it is reported separately as a known
                    limitation.

Tuning was done on seed 0 only; the reported numbers use seeds 1-10.

    python benchmarks/fraud_benchmark.py            # print results
    python benchmarks/fraud_benchmark.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sakshi.fraud import detect_collusion  # noqa: E402
from sakshi.orders import OrderView  # noqa: E402

DAY = 86400
SPAN = 30 * DAY


def generate(seed: int) -> tuple[list[OrderView], dict[str, str]]:
    rng = random.Random(seed)
    orders: list[OrderView] = []
    labels: dict[str, str] = {}
    n = 0

    def order(seller: str, buyer: str, ts: int, price: int, delivery_min: float, promised_min: float) -> None:
        nonlocal n
        n += 1
        delivered = ts + int(delivery_min * 60)
        orders.append(OrderView(order_id=f"o{n}", seller_id=seller, bpp_id="bpp", bap_id="bap", buyer_ref=buyer,
                                contracted_at=ts, price=price, promised_by=ts + int(promised_min * 60),
                                contract_index=n, delivered_at=delivered, fulfilment_index=n))

    # --- honest sellers, spread over 4 cities
    honest = []
    for i in range(160):
        s = f"seller-{i:03d}"
        labels[s] = "honest"
        honest.append((s, i % 4, rng.lognormvariate(0, 1.0), rng.lognormvariate(5.8, 0.7),
                       rng.lognormvariate(4.5, 0.6)))
    for i in range(25):
        s = f"new-{i:02d}"
        labels[s] = "new"
        honest.append((s, i % 4, 0.05, rng.lognormvariate(5.8, 0.7), rng.lognormvariate(4.5, 0.6)))

    def place(seller_spec, buyer: str) -> None:
        s, _city, _pop, price_level, speed = seller_spec
        ts = rng.randrange(SPAN)
        price = max(2000, int(rng.lognormvariate(0, 0.45) * price_level * 100))
        delivery = max(10.0, rng.lognormvariate(0, 0.35) * speed)
        order(s, buyer, ts, price, delivery, speed * 1.6)

    by_city = {c: [h for h in honest if h[1] == c] for c in range(4)}
    for b in range(3500):
        buyer = f"buyer-{b:05d}"
        city = b % 4
        for _ in range(max(1, int(rng.expovariate(1 / 5)))):
            pool = by_city[city] if rng.random() < 0.9 else honest      # some cross-city shopping
            place(rng.choices(pool, weights=[p[2] for p in pool])[0], buyer)

    # --- hard negatives: loyal neighbourhood shops
    for i in range(12):
        s = f"local-{i:02d}"
        labels[s] = "loyal_local"
        spec = (s, i % 4, 0, rng.lognormvariate(5.5, 0.5), rng.lognormvariate(4.0, 0.4))
        regulars = rng.randint(8, 25)
        for r in range(regulars):
            for _ in range(rng.randint(2, 10)):
                place(spec, f"regular-{i}-{r}")
        for _ in range(rng.randint(0, 15)):            # a few walk-ins from the wider network
            place(spec, f"buyer-{rng.randrange(3500):05d}")

    # --- fraud
    def boost(sellers: list[str], n_fake: int, camouflage: bool, tag: str) -> None:
        start = rng.randrange(SPAN - 4 * DAY)
        price = rng.randint(4900, 9900)                     # small, near-identical baskets
        for f in range(n_fake):
            fake = f"{tag}-fake-{f}"
            for _ in range(rng.randint(2, 7)):
                order(rng.choice(sellers), fake, start + rng.randrange(3 * DAY),
                      price + rng.randint(-200, 200), rng.uniform(1, 8), 60)
            if camouflage:                                  # one decoy order to look real
                place(rng.choice(honest), fake)

    def genuine_trickle(s: str, k: int) -> None:
        spec = (s, 0, 0, rng.lognormvariate(5.8, 0.7), rng.lognormvariate(4.5, 0.6))
        for _ in range(k):
            place(spec, f"buyer-{rng.randrange(3500):05d}")

    for i in range(8):
        s = f"fraud-sybil-{i}"
        labels[s] = "sybil"
        genuine_trickle(s, rng.randint(0, 15))
        boost([s], rng.randint(8, 30), False, s)
    for i in range(3):
        ring = [f"fraud-ring{i}-{j}" for j in range(rng.randint(2, 3))]
        for s in ring:
            labels[s] = "ring"
            genuine_trickle(s, rng.randint(0, 10))
        boost(ring, rng.randint(15, 40), False, f"ring{i}")
    for i in range(5):
        s = f"fraud-camo-{i}"
        labels[s] = "camouflaged"
        genuine_trickle(s, rng.randint(0, 15))
        boost([s], rng.randint(8, 30), True, s)
    for i in range(4):
        s = f"fraud-adaptive-{i}"
        labels[s] = "adaptive"
        spec = (s, 0, 0, rng.lognormvariate(5.8, 0.5), rng.lognormvariate(4.5, 0.4))
        genuine_trickle(s, rng.randint(0, 15))
        for f in range(rng.randint(10, 30)):
            for _ in range(rng.randint(2, 6)):
                place(spec, f"{s}-fake-{f}")
    return orders, labels


FRAUD = ("sybil", "ring", "camouflaged")       # headline metrics; "adaptive" reported separately


def evaluate(seed: int) -> dict:
    orders, labels = generate(seed)
    results = detect_collusion(orders=orders)
    flagged = {r.seller_id for r in results if r.flagged}
    judged = {r.seller_id for r in results}
    fraud = {s for s, lbl in labels.items() if lbl in FRAUD and s in judged}
    adaptive = {s for s, lbl in labels.items() if lbl == "adaptive"}
    tp, fn = len(flagged & fraud), len(fraud - flagged)
    fp = len(flagged - fraud - adaptive)          # flagging an adaptive fraudster is not a false positive
    per_type = {}
    for t in ("sybil", "ring", "camouflaged", "adaptive", "loyal_local", "honest", "new"):
        members = {s for s, lbl in labels.items() if lbl == t and s in judged}
        per_type[t] = {"total": len(members), "flagged": len(members & flagged)}
    return {"seed": seed, "sellers": len(judged), "orders": len(orders), "tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else 1.0, "recall": tp / (tp + fn) if tp + fn else 1.0,
            "per_type": per_type}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--first-seed", type=int, default=1)
    ap.add_argument("--json")
    args = ap.parse_args()
    runs = [evaluate(s) for s in range(args.first_seed, args.first_seed + args.seeds)]
    p = [r["precision"] for r in runs]
    r_ = [r["recall"] for r in runs]
    f1 = [2 * a * b / (a + b) if a + b else 0 for a, b in zip(p, r_, strict=True)]
    totals: dict[str, dict[str, int]] = {}
    for run in runs:
        for t, v in run["per_type"].items():
            agg = totals.setdefault(t, {"total": 0, "flagged": 0})
            agg["total"] += v["total"]
            agg["flagged"] += v["flagged"]
    summary = {
        "seeds": [r["seed"] for r in runs],
        "sellers_per_run": runs[0]["sellers"],
        "orders_per_run": runs[0]["orders"],
        "precision_mean": round(statistics.fmean(p), 3), "precision_min": round(min(p), 3),
        "recall_mean": round(statistics.fmean(r_), 3), "recall_min": round(min(r_), 3),
        "f1_mean": round(statistics.fmean(f1), 3),
        "flag_rate_by_population": {t: f"{v['flagged']}/{v['total']} ({v['flagged'] / v['total']:.0%})"
                                    for t, v in totals.items() if v["total"]},
    }
    print(json.dumps(summary, indent=2))
    if args.json:
        Path(args.json).write_text(json.dumps({"summary": summary, "runs": runs}, indent=2))


if __name__ == "__main__":
    main()
