import pytest

from sakshi.disputes import decide
from sakshi.orders import LedgerEntry, OrderView, build_orders, to_paise
from sakshi.receipts import new_receipt
from sakshi.reputation import compute_reputation
from tests.conftest import Party

T0 = 1_000_000


class Log:
    def __init__(self):
        self.entries = []

    def add(self, type_, order_id, terms, seller="shop", issuer="bpp", issued_at=T0):
        body = {"type": type_, "issuer": issuer, "counterparty": "bap", "transaction_id": "t", "order_id": order_id,
                "seller_id": seller, "buyer_ref": "b1", "terms": terms, "issued_at": issued_at, "evidence": {}, "v": 1}
        self.entries.append(LedgerEntry(len(self.entries), issued_at, {"body": body, "signatures": []}))

    def order(self, oid, seller="shop", at=T0, promise=600, delivered_after=None, cancelled=False):
        self.add("ORDER_CONTRACT", oid, {"price": {"currency": "INR", "value": "100.00"},
                                         "promised_delivery_by": at + promise}, seller, issued_at=at)
        if delivered_after is not None:
            self.add("FULFILMENT", oid, {"delivered_at": at + delivered_after}, seller, issued_at=at + delivered_after)
        if cancelled:
            self.add("CANCELLATION", oid, {"cancelled_by": "seller"}, seller, issued_at=at + 10)


def test_to_paise():
    assert to_paise("499.5") == 49950
    assert to_paise("12") == 1200
    assert to_paise("0.07") == 7


def test_reputation_counts_and_ordering():
    log = Log()
    for i in range(10):
        log.order(f"good{i}", "good", delivered_after=300)
        log.order(f"bad{i}", "bad", promise=60)                  # never delivered
    for i in range(3):
        log.order(f"late{i}", "late", delivered_after=900)
    reps = compute_reputation(log.entries, as_of=T0 + 10_000)
    assert reps["good"].on_time == 10 and reps["good"].score > 90
    assert reps["bad"].undelivered_overdue == 10 and reps["bad"].score < 20
    assert reps["late"].late == 3
    assert reps["good"].score > reps["late"].score > reps["bad"].score


def test_new_sellers_start_near_a_neutral_prior():
    log = Log()
    log.order("o1", "newbie", delivered_after=100)
    rep = compute_reputation(log.entries, as_of=T0 + 1000)["newbie"]
    assert 60 < rep.score < 90                                  # one good order is not "100%"
    assert rep.confidence == "new"


def test_pending_orders_dont_count_until_overdue():
    log = Log()
    log.order("o1", "shop", promise=600)
    assert compute_reputation(log.entries, as_of=T0 + 100)["shop"].undelivered_overdue == 0
    assert compute_reputation(log.entries, as_of=T0 + 700)["shop"].undelivered_overdue == 1


def test_reputation_is_deterministic():
    log = Log()
    for i in range(5):
        log.order(f"o{i}", "shop", delivered_after=200 + 200 * i)
    a = compute_reputation(log.entries, as_of=T0 + 5000)
    b = compute_reputation(list(log.entries), as_of=T0 + 5000)
    assert a["shop"].to_dict() == b["shop"].to_dict()


def test_lost_disputes_hurt():
    log = Log()
    for i in range(5):
        log.order(f"o{i}", "shop", delivered_after=100)
    before = compute_reputation(log.entries, as_of=T0 + 9999)["shop"].score
    log.add("DISPUTE_VERDICT", "o0", {"claim": "X", "outcome": "BUYER_WINS"}, "shop", issuer="witness")
    assert compute_reputation(log.entries, as_of=T0 + 9999)["shop"].score < before


# ------------------------------------------------------------------- disputes
def view(**kw) -> OrderView:
    d = dict(order_id="o", seller_id="s", bpp_id="bpp", bap_id="bap", buyer_ref="b", contracted_at=T0, price=10000,
             promised_by=T0 + 600, contract_index=0)
    d.update(kw)
    return OrderView(**d)


@pytest.mark.parametrize("claim,order,as_of,outcome", [
    ("NOT_DELIVERED", view(), T0 + 700, "BUYER_WINS"),
    ("NOT_DELIVERED", view(), T0 + 100, "REJECTED"),                                  # too early
    ("NOT_DELIVERED", view(delivered_at=T0 + 500, fulfilment_index=1), T0 + 900, "SELLER_WINS"),
    ("NOT_DELIVERED", view(cancelled_by="seller", cancellation_index=1), T0 + 900, "REJECTED"),
    ("NOT_DELIVERED", None, T0, "REJECTED"),                                          # nothing was agreed
    ("LATE_DELIVERY", view(delivered_at=T0 + 900, fulfilment_index=1), T0 + 900, "BUYER_WINS"),
    ("LATE_DELIVERY", view(delivered_at=T0 + 500, fulfilment_index=1), T0 + 900, "SELLER_WINS"),
    ("ITEM_NOT_AS_DESCRIBED", view(), T0, "NEEDS_HUMAN_REVIEW"),
    ("MADE_UP_CLAIM", view(), T0, "REJECTED"),
])
def test_dispute_rules(claim, order, as_of, outcome):
    v = decide(claim, order, as_of)
    assert v.outcome == outcome
    if outcome in ("BUYER_WINS", "SELLER_WINS"):
        assert v.evidence                                   # every decision cites its evidence


def test_price_mismatch_uses_sellers_own_signatures():
    seller, buyer = Party("seller.app"), Party("buyer.app")

    def stmt(type_, price, txn="t1", issuer=seller):
        return new_receipt(type_, issuer.id, buyer.id, txn, "o1", "shop", "b",
                           {"price": {"currency": "INR", "value": price}})
    assert decide("PRICE_MISMATCH", None, T0, [stmt("QUOTE", "100.00"), stmt("ORDER_CONTRACT", "125.00")]).outcome == "BUYER_WINS"
    assert decide("PRICE_MISMATCH", None, T0, [stmt("QUOTE", "100.00"), stmt("ORDER_CONTRACT", "100.00")]).outcome == "SELLER_WINS"
    assert decide("PRICE_MISMATCH", None, T0, [stmt("QUOTE", "100.00")]).outcome == "REJECTED"
    other = decide("PRICE_MISMATCH", None, T0, [stmt("QUOTE", "1.00", txn="t2"), stmt("ORDER_CONTRACT", "125.00")])
    assert other.rule == "unrelated-evidence"


def test_build_orders_ignores_events_after_close():
    log = Log()
    log.order("o1", delivered_after=100)
    log.add("CANCELLATION", "o1", {"cancelled_by": "seller"})          # can't cancel a delivered order
    orders, _ = build_orders(log.entries)
    assert orders["o1"].delivered_at is not None and orders["o1"].cancelled_by is None
