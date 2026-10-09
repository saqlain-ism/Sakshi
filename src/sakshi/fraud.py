"""Collusion and fake-boosting detection.

Signatures prove *what happened*, not that it was *genuine commerce*. A
seller can create fake buyer accounts, place orders with itself and
"deliver" them, and every receipt will be validly signed. This is the
classic attack on any reputation system (a Sybil attack), so it needs a
separate defence. Two independent signals are combined.

**1. Graph signal: captive buyers.**
Project the buyer-seller graph onto sellers: two sellers are linked when
they share an unusually large fraction of their buyers (Jaccard
similarity). Connected groups of such sellers are candidate **rings**.
For each seller, a buyer is *captive* when at least 75% of that buyer's
orders go to the seller or its ring. Real shoppers spread their orders;
fake accounts exist only to boost one seller or ring.

**2. Behaviour signal: does the trade look real?**
Fake orders tend to look unnatural: near-instant "delivery" (nothing
physical moves), small uniform baskets, and bursts of activity. An
IsolationForest (unsupervised, because no fraud labels exist on day one)
learns what normal sellers look like on these features and scores how far
each seller deviates.

A seller is **flagged** only when *both* agree. The graph signal alone also
fires on honest neighbourhood shops with loyal regulars, and the behaviour
signal alone fires on honest outliers. Flags go to human review; they
never silently change anyone's score.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field

import networkx as nx
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from .orders import LedgerEntry, OrderView, build_orders

GRAPH_FEATURES = ["captive_share", "repeat_ratio"]
BEHAVIOUR_FEATURES = ["delivery_fraction", "value_ratio", "burst_share", "price_cv"]
FAST_DELIVERY = 0.1           # delivered within 10% of the promised window: implausibly fast
MIN_ORDERS = 5
RING_JACCARD = 0.15          # sellers sharing at least this fraction of buyers are linked
RING_MIN_SHARED = 3          # ... and at least this many buyers in common
RING_BUYER_MAX_SELLERS = 3   # only buyers who shop at a handful of sellers can tie sellers into a ring
RING_MAX_SIZE = 5            # a "ring" bigger than this is just normal market overlap ...
RING_MAX_SHARE = 0.25        # ... as is one containing a quarter of the whole market
CAPTIVE_CONCENTRATION = 0.75
MIN_BUYER_ORDERS = 2         # a buyer with a single order tells us nothing about loyalty
SMALL_NETWORK = 12           # below this many sellers there is no population to learn "normal" from


@dataclass
class SellerRisk:
    seller_id: str
    orders: int
    features: dict[str, float]
    behaviour_score: float               # 0-1, how unusual the trading behaviour is
    collusion_signal: float              # share of orders from captive buyers
    flagged: bool
    reasons: list[str] = field(default_factory=list)
    ring: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def find_rings(by_seller_buyers: dict[str, set[str]]) -> dict[str, list[str]]:
    """Sellers linked by heavily shared buyers, as connected groups."""
    buyer_sellers: dict[str, set[str]] = defaultdict(set)
    for s, buyers in by_seller_buyers.items():
        for b in buyers:
            buyer_sellers[b].add(s)
    shared: Counter[tuple[str, str]] = Counter()
    for sellers in buyer_sellers.values():
        # Shoppers who spread across many sellers are what *normal* looks like; only buyers
        # concentrated on a few sellers can be the shared sock puppets of a ring.
        if 1 < len(sellers) <= RING_BUYER_MAX_SELLERS:
            ss = sorted(sellers)
            for i, a in enumerate(ss):
                for b in ss[i + 1:]:
                    shared[(a, b)] += 1
    g = nx.Graph()
    for (a, b), k in shared.items():
        union = len(by_seller_buyers[a] | by_seller_buyers[b])
        if k >= RING_MIN_SHARED and k / union >= RING_JACCARD:
            g.add_edge(a, b, weight=k / union)
    rings: dict[str, list[str]] = {}
    for comp in nx.connected_components(g):
        if len(comp) > min(RING_MAX_SIZE, max(2, int(len(by_seller_buyers) * RING_MAX_SHARE))):
            continue
        for s in comp:
            rings[s] = sorted(comp - {s})
    return rings


def seller_features(orders: list[OrderView]) -> tuple[dict[str, dict[str, float]], dict[str, list[str]], dict[str, int]]:
    by_seller: dict[str, list[OrderView]] = defaultdict(list)
    buyer_orders: dict[str, Counter[str]] = defaultdict(Counter)
    for o in orders:
        by_seller[o.seller_id].append(o)
        buyer_orders[o.buyer_ref][o.seller_id] += 1

    rings = find_rings({s: {o.buyer_ref for o in os_} for s, os_ in by_seller.items()})
    network_median = statistics.median(o.price for o in orders) if orders else 1
    t0 = min((o.contracted_at for o in orders), default=0)
    t1 = max((o.contracted_at for o in orders), default=1)
    window = max(3600, (t1 - t0) / 30)

    feats: dict[str, dict[str, float]] = {}
    counts: dict[str, int] = {}
    for seller, os_ in by_seller.items():
        n = len(os_)
        counts[seller] = n
        group = {seller, *rings.get(seller, [])}
        buyers = Counter(o.buyer_ref for o in os_)
        captive = 0
        for b, c in buyers.items():
            total = sum(buyer_orders[b].values())
            if total < MIN_BUYER_ORDERS:
                continue
            in_group = sum(k for s, k in buyer_orders[b].items() if s in group)
            if in_group / total >= CAPTIVE_CONCENTRATION:
                captive += c
        # Delivery speed relative to the seller's own promise, so it works for any time scale:
        # a 30-min grocery promise and a 3-day courier promise both give comparable numbers.
        delivered = [(o.delivered_at - o.contracted_at) / max(1, o.promised_by - o.contracted_at)
                     for o in os_ if o.delivered_at is not None]
        prices = [o.price for o in os_]
        times = sorted(o.contracted_at for o in os_)
        feats[seller] = {
            "captive_share": captive / n,
            "repeat_ratio": 1 - len(buyers) / n,
            "delivery_fraction": statistics.median(delivered) if delivered else 1.0,
            "value_ratio": math.log((statistics.median(prices) + 1) / (network_median + 1)),
            "burst_share": max(_count_in_window(times, i, window) for i in range(n)) / n,
            "price_cv": statistics.pstdev(prices) / statistics.fmean(prices),
        }
    return feats, rings, counts


def _count_in_window(times: list[int], i: int, window: float) -> int:
    j, end = i, times[i] + window
    while j < len(times) and times[j] <= end:
        j += 1
    return j - i


def _behaviour_scores(x: np.ndarray, random_state: int) -> np.ndarray:
    """0 for typical sellers, towards 1 for the most unusual."""
    xs = RobustScaler().fit_transform(x)
    model = IsolationForest(n_estimators=300, random_state=random_state).fit(xs)
    raw = -model.score_samples(xs)                 # about 0.4 typical, up to about 0.8 for strong outliers
    return np.clip((raw - 0.45) / 0.25, 0, 1)


def detect_collusion(entries: list[LedgerEntry] | None = None, orders: list[OrderView] | None = None,
                     collusion_threshold: float = 0.5, behaviour_threshold: float = 0.2,
                     random_state: int = 0) -> list[SellerRisk]:
    if orders is None:
        orders = list(build_orders(entries or [])[0].values())
    feats, rings, counts = seller_features(orders)
    sellers = sorted(s for s in feats if counts[s] >= MIN_ORDERS)
    if not sellers:
        return []

    x = np.array([[feats[s][f] for f in BEHAVIOUR_FEATURES] for s in sellers])
    small = len(sellers) < SMALL_NETWORK
    # With very few sellers there is no "normal" population to learn from, so behaviour is
    # judged by one physical sanity limit instead: goods can't be delivered in a few % of
    # the promised time when nothing is actually shipped.
    scores = (np.array([1.0 if feats[s]["delivery_fraction"] < FAST_DELIVERY else 0.0 for s in sellers])
              if small else _behaviour_scores(x, random_state))

    med = np.median(x, axis=0)
    mad = np.median(np.abs(x - med), axis=0) + 1e-9
    labels = {"delivery_fraction": "delivery speed", "value_ratio": "order value",
              "burst_share": "burstiness", "price_cv": "order-value spread"}
    results: list[SellerRisk] = []
    for i, s in enumerate(sellers):
        f = feats[s]
        collusion = f["captive_share"]
        flagged = collusion >= collusion_threshold and scores[i] >= behaviour_threshold
        reasons: list[str] = []
        if collusion >= collusion_threshold:
            who = "this seller" if not rings.get(s) else f"this seller and {', '.join(rings[s])}"
            reasons.append(f"{collusion:.0%} of orders come from buyers who shop almost only at {who}")
            if f["delivery_fraction"] < FAST_DELIVERY:
                reasons.append(f"orders 'delivered' in {f['delivery_fraction']:.0%} of the promised time (nothing physical moves that fast)")
            if not small:
                for j, name in enumerate(BEHAVIOUR_FEATURES):
                    z = (x[i, j] - med[j]) / (1.4826 * mad[j])
                    if abs(z) >= 3 and name != "delivery_fraction":
                        reasons.append(f"unusual {labels[name]} ({'high' if z > 0 else 'low'}, {abs(z):.1f} MAD)")
            if not flagged:
                reasons.append("trading pattern looks genuine (e.g. a local shop with regulars): not flagged")
        results.append(SellerRisk(s, counts[s], {k: round(v, 4) for k, v in f.items()},
                                  round(float(scores[i]), 3), round(collusion, 3), bool(flagged),
                                  reasons, rings.get(s, []) if flagged else []))
    results.sort(key=lambda r: (not r.flagged, -r.collusion_signal * r.behaviour_score, r.seller_id))
    return results

