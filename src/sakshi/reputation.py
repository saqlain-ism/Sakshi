"""Verifiable seller reputation.

Star ratings are cheap to fake and impossible to audit. Here a seller's
score is a **pure function of the transparency log**:

    score = f(entries[0 : tree_size], as_of)

Every input is a receipt countersigned by both parties or a signed dispute
verdict, and the function is deterministic. So anyone holding a signed tree
head can download those entries, recompute the score and get exactly the
same number. A buyer app, a regulator or the seller can all check that the
score wasn't massaged.

Scoring is Bayesian (a Beta prior). A seller with 1 good order out of 1
isn't "100%": newcomers start near a neutral prior and the evidence pulls
the score as orders accumulate. `confidence` tells consumers how much
evidence stands behind the number.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .orders import LedgerEntry, build_orders

PRIOR_GOOD = 2.0          # Beta prior: as if every seller started with 2 good ...
PRIOR_BAD = 1.0           # ... and 1 bad outcome (about 67% on day one)
LATE_CREDIT = 0.5         # a late delivery counts half
DELIVERY_GRACE_S = 0      # deadline grace before an undelivered order counts as failed


@dataclass
class Reputation:
    seller_id: str
    score: float              # 0-100
    confidence: str           # new / low / medium / high
    orders: int
    on_time: int
    late: int
    seller_cancellations: int
    undelivered_overdue: int
    disputes_lost: int
    disputes_won: int
    on_time_rate: float | None

    def to_dict(self) -> dict:
        return asdict(self)


def _confidence(resolved: int) -> str:
    return "new" if resolved < 3 else "low" if resolved < 10 else "medium" if resolved < 50 else "high"


def compute_reputation(entries: list[LedgerEntry], as_of: int, grace_s: int = DELIVERY_GRACE_S) -> dict[str, Reputation]:
    orders, verdicts = build_orders(entries)
    stats: dict[str, dict[str, int]] = {}

    def s(seller: str) -> dict[str, int]:
        return stats.setdefault(seller, dict(orders=0, on_time=0, late=0, cancel=0, overdue=0, lost=0, won=0))

    for o in orders.values():
        st = s(o.seller_id)
        st["orders"] += 1
        if o.delivered_at is not None:
            st["on_time" if o.on_time else "late"] += 1
        elif o.cancelled_by == "seller":
            st["cancel"] += 1
        elif o.overdue(as_of, grace_s):
            st["overdue"] += 1

    for v in verdicts:
        t = v.body["terms"]
        st = s(v.body["seller_id"])
        if t["outcome"] == "BUYER_WINS":
            st["lost"] += 1
        elif t["outcome"] == "SELLER_WINS":
            st["won"] += 1

    result: dict[str, Reputation] = {}
    for seller, st in sorted(stats.items()):
        resolved = st["on_time"] + st["late"] + st["cancel"] + st["overdue"]
        good = st["on_time"] + LATE_CREDIT * st["late"]
        reliability = (good + PRIOR_GOOD) / (resolved + PRIOR_GOOD + PRIOR_BAD)
        # Each dispute lost weighs like two failed orders.
        disputes = st["lost"] / (resolved + st["lost"] + PRIOR_GOOD + PRIOR_BAD)
        score = 100.0 * reliability * max(0.0, 1.0 - 2.0 * disputes)
        delivered = st["on_time"] + st["late"]
        result[seller] = Reputation(
            seller_id=seller, score=round(score, 1), confidence=_confidence(resolved + st["lost"]),
            orders=st["orders"], on_time=st["on_time"], late=st["late"], seller_cancellations=st["cancel"],
            undelivered_overdue=st["overdue"], disputes_lost=st["lost"], disputes_won=st["won"],
            on_time_rate=round(st["on_time"] / delivered, 3) if delivered else None,
        )
    return result
