"""Folds ledger entries into one view per order.

Reputation, dispute resolution and fraud detection all read the log through
this module, so they agree on what each order's history says.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class LedgerEntry:
    index: int
    logged_at: int
    receipt: dict           # {"body": ..., "signatures": [...]}

    @property
    def body(self) -> dict:
        return self.receipt["body"]

    @property
    def type(self) -> str:
        return self.body["type"]


@dataclass
class OrderView:
    order_id: str
    seller_id: str
    bpp_id: str
    bap_id: str
    buyer_ref: str
    contracted_at: int
    price: int                       # paise (integer, never float)
    promised_by: int
    contract_index: int
    delivered_at: int | None = None
    fulfilment_index: int | None = None
    cancelled_by: str | None = None
    cancellation_index: int | None = None
    verdicts: list[dict] = field(default_factory=list)

    @property
    def on_time(self) -> bool:
        return self.delivered_at is not None and self.delivered_at <= self.promised_by

    def overdue(self, as_of: int, grace_s: int) -> bool:
        return self.delivered_at is None and self.cancelled_by is None and as_of > self.promised_by + grace_s


def to_paise(amount: str) -> int:
    """'499.50' -> 49950. Decimal strings in, integers out: no float rounding."""
    rupees, _, paise = amount.partition(".")
    return int(rupees) * 100 + int((paise + "00")[:2])


def build_orders(entries: list[LedgerEntry]) -> tuple[dict[str, OrderView], list[LedgerEntry]]:
    """Returns (orders by id, verdict entries)."""
    orders: dict[str, OrderView] = {}
    verdicts: list[LedgerEntry] = []
    for e in entries:
        b = e.body
        t = b["type"]
        if t == "ORDER_CONTRACT":
            terms = b["terms"]
            orders[b["order_id"]] = OrderView(
                order_id=b["order_id"], seller_id=b["seller_id"], bpp_id=b["issuer"], bap_id=b["counterparty"],
                buyer_ref=b["buyer_ref"], contracted_at=b["issued_at"], price=to_paise(terms["price"]["value"]),
                promised_by=terms["promised_delivery_by"], contract_index=e.index)
        elif t == "FULFILMENT" and b["order_id"] in orders:
            o = orders[b["order_id"]]
            if o.delivered_at is None:
                o.delivered_at, o.fulfilment_index = b["terms"]["delivered_at"], e.index
        elif t == "CANCELLATION" and b["order_id"] in orders:
            o = orders[b["order_id"]]
            if o.cancelled_by is None and o.delivered_at is None:
                o.cancelled_by, o.cancellation_index = b["terms"]["cancelled_by"], e.index
        elif t == "DISPUTE_VERDICT":
            verdicts.append(e)
            if b["order_id"] in orders:
                orders[b["order_id"]].verdicts.append(b["terms"])
    return orders, verdicts
