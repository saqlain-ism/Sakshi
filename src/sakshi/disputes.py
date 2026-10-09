"""Evidence-based dispute resolution.

ONDC's grievance process (IGM) escalates through support desks,
grievance officers and finally online dispute resolution. Most disputes,
though, are factual and the evidence already exists: was it delivered, was
it late, was the price changed? With signed receipts those questions have
cryptographic answers, so they can be decided instantly and the same way
every time. That leaves human reviewers only the genuinely subjective cases
("the item is damaged").

Every verdict lists the exact evidence it relied on (ledger indices and
receipt hashes), so anyone can re-run the decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .orders import OrderView, to_paise
from .receipts import Receipt

CLAIMS = {"NOT_DELIVERED", "LATE_DELIVERY", "PRICE_MISMATCH", "ITEM_NOT_AS_DESCRIBED"}


@dataclass
class Verdict:
    claim: str
    outcome: str                 # BUYER_WINS / SELLER_WINS / REJECTED / NEEDS_HUMAN_REVIEW
    rule: str
    reason: str
    evidence: list[dict] = field(default_factory=list)
    remedy: str | None = None

    def to_terms(self) -> dict:
        return {"claim": self.claim, "outcome": self.outcome, "rule": self.rule, "reason": self.reason,
                "evidence": self.evidence, "remedy": self.remedy}


def _ev(kind: str, **kw) -> dict:
    return {"kind": kind, **kw}


def decide(claim: str, order: OrderView | None, as_of: int, evidence: list[Receipt] | None = None,
           grace_s: int = 0) -> Verdict:
    """Pure decision function. Evidence receipts must already be signature-verified."""
    if claim not in CLAIMS:
        return Verdict(claim, "REJECTED", "unknown-claim", f"unsupported claim type {claim}")

    if claim == "PRICE_MISMATCH":
        return _price_mismatch(evidence or [])

    if claim == "ITEM_NOT_AS_DESCRIBED":
        return Verdict(claim, "NEEDS_HUMAN_REVIEW", "subjective",
                       "item condition can't be established from receipts; routed to a grievance officer",
                       [_ev("contract", ledger_index=order.contract_index)] if order else [])

    if order is None:
        return Verdict(claim, "REJECTED", "no-contract",
                       "no countersigned order contract in the ledger: nothing was agreed")
    contract = _ev("contract", ledger_index=order.contract_index, promised_by=order.promised_by)

    if claim == "NOT_DELIVERED":
        if order.delivered_at is not None:
            return Verdict(claim, "SELLER_WINS", "delivery-receipt-exists",
                           "a delivery receipt countersigned by the buyer's app is in the ledger",
                           [contract, _ev("fulfilment", ledger_index=order.fulfilment_index,
                                          delivered_at=order.delivered_at)])
        if order.cancelled_by is not None:
            return Verdict(claim, "REJECTED", "order-cancelled", f"order was cancelled by the {order.cancelled_by}",
                           [contract, _ev("cancellation", ledger_index=order.cancellation_index)])
        if as_of <= order.promised_by + grace_s:
            return Verdict(claim, "REJECTED", "deadline-not-passed",
                           "the promised delivery time has not passed yet", [contract])
        return Verdict(claim, "BUYER_WINS", "no-delivery-by-deadline",
                       f"seller promised delivery by {order.promised_by}; no countersigned delivery receipt exists",
                       [contract, _ev("absence", checked_until=as_of)], remedy="FULL_REFUND")

    # LATE_DELIVERY
    if order.delivered_at is None:
        return Verdict(claim, "REJECTED", "not-delivered", "no delivery recorded; file NOT_DELIVERED instead", [contract])
    fulfil = _ev("fulfilment", ledger_index=order.fulfilment_index, delivered_at=order.delivered_at)
    if order.delivered_at > order.promised_by:
        late_min = (order.delivered_at - order.promised_by) // 60
        return Verdict(claim, "BUYER_WINS", "delivered-after-promise",
                       f"delivered {late_min} min after the signed promise", [contract, fulfil],
                       remedy="DELIVERY_FEE_REFUND")
    return Verdict(claim, "SELLER_WINS", "delivered-on-time", "delivery receipt is within the promised time",
                   [contract, fulfil])


def _price_mismatch(evidence: list[Receipt]) -> Verdict:
    """Bait-and-switch: the seller quoted one price, then confirmed another.

    Both documents carry the seller's own signature, so no countersignature
    is needed. A statement signed by X is evidence against X.
    """
    quote = next((r for r in evidence if r.body["type"] == "QUOTE"), None)
    contract = next((r for r in evidence if r.body["type"] == "ORDER_CONTRACT"), None)
    if quote is None or contract is None:
        return Verdict("PRICE_MISMATCH", "REJECTED", "missing-evidence", "needs the seller-signed quote and confirmation")
    if quote.issuer != contract.issuer or quote.body["transaction_id"] != contract.body["transaction_id"]:
        return Verdict("PRICE_MISMATCH", "REJECTED", "unrelated-evidence",
                       "quote and confirmation are from different sellers or transactions")
    q, c = to_paise(quote.body["terms"]["price"]["value"]), to_paise(contract.body["terms"]["price"]["value"])
    ev = [_ev("quote", receipt_id=quote.receipt_id, price=quote.body["terms"]["price"]["value"]),
          _ev("confirmation", receipt_id=contract.receipt_id, price=contract.body["terms"]["price"]["value"])]
    if c > q:
        return Verdict("PRICE_MISMATCH", "BUYER_WINS", "confirmed-above-quote",
                       f"seller signed a quote of Rs {q / 100:.2f} and then a confirmation of Rs {c / 100:.2f}",
                       ev, remedy="ORDER_VOIDED")
    return Verdict("PRICE_MISMATCH", "SELLER_WINS", "price-honoured", "confirmed price does not exceed the quote", ev)
