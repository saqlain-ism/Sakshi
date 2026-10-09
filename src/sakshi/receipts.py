"""Signed commitments ("receipts") - the core idea of Sakshi.

ONDC's request signatures prove *who sent a message*. They don't leave either
side holding portable proof of *what was agreed*: each app keeps its own logs,
and in a dispute it's one database against another.

A receipt is a small, canonical statement about one step of an order
("seller X committed to deliver these items for Rs 499 by Tuesday"). It is:

1. signed by the **issuer** (the party making the commitment), and
2. countersigned by the **counterparty**, acknowledging they received
   exactly that.

Once both signatures exist, neither side can later deny it (non-repudiation),
and anyone holding the issuer's and counterparty's public keys can check it.
Receipts are then appended to the transparency log (see merkle.py).

Signatures are domain-separated (a fixed prefix per purpose), so a signature
made for a receipt can never be replayed as a signature on something else,
such as a request or a tree head.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

from .auth import KeyResolver
from .canonical import canonical_json
from .crypto import b64d, sign, verify

RECEIPT_TYPES = {"QUOTE", "ORDER_CONTRACT", "FULFILMENT", "CANCELLATION", "DISPUTE_VERDICT"}
# Statements that bind only their issuer and need no countersignature:
# a quote binds the seller, and a dispute verdict is issued by the witness.
SINGLE_SIGNED = {"QUOTE", "DISPUTE_VERDICT"}
_ISSUE_PREFIX = b"sakshi/receipt/v1\n"
_COUNTER_PREFIX = b"sakshi/receipt-countersign/v1\n"


class ReceiptError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass
class Receipt:
    body: dict[str, Any]
    signatures: list[dict[str, str]] = field(default_factory=list)

    # ---------------------------------------------------------------- identity
    @property
    def receipt_id(self) -> str:
        return hashlib.sha256(canonical_json(self.body)).hexdigest()

    @property
    def issuer(self) -> str:
        return self.body["issuer"]

    @property
    def counterparty(self) -> str:
        return self.body["counterparty"]

    def to_dict(self) -> dict:
        return {"body": self.body, "signatures": self.signatures}

    @classmethod
    def from_dict(cls, data: dict) -> Receipt:
        return cls(body=data["body"], signatures=list(data.get("signatures", [])))

    def to_bytes(self) -> bytes:
        """Canonical bytes of the whole receipt: what gets logged and hashed."""
        return canonical_json(self.to_dict())

    # ---------------------------------------------------------------- signing
    def _issue_message(self) -> bytes:
        return _ISSUE_PREFIX + canonical_json(self.body)

    def _counter_message(self, issuer_sig: str) -> bytes:
        return _COUNTER_PREFIX + canonical_json(self.body) + b"\n" + b64d(issuer_sig)

    def sign_as_issuer(self, key_id: str, private_key_b64: str) -> Receipt:
        if self.signatures:
            raise ReceiptError("RECEIPT_ALREADY_SIGNED", "issuer must sign first")
        self.signatures.append({"role": "issuer", "signer": self.issuer, "key_id": key_id,
                                "sig": sign(private_key_b64, self._issue_message())})
        return self

    def countersign(self, key_id: str, private_key_b64: str) -> Receipt:
        if len(self.signatures) != 1 or self.signatures[0]["role"] != "issuer":
            raise ReceiptError("RECEIPT_NOT_ISSUED", "countersign needs exactly the issuer signature")
        self.signatures.append({"role": "counterparty", "signer": self.counterparty, "key_id": key_id,
                                "sig": sign(private_key_b64, self._counter_message(self.signatures[0]["sig"]))})
        return self


def new_receipt(type_: str, issuer: str, counterparty: str, transaction_id: str, order_id: str,
                seller_id: str, buyer_ref: str, terms: dict, evidence: dict | None = None,
                issued_at: int | None = None) -> Receipt:
    if type_ not in RECEIPT_TYPES:
        raise ReceiptError("RECEIPT_TYPE", f"unknown receipt type {type_}")
    return Receipt(body={
        "v": 1,
        "type": type_,
        "issuer": issuer,
        "counterparty": counterparty,
        "transaction_id": transaction_id,
        "order_id": order_id,
        "seller_id": seller_id,
        "buyer_ref": buyer_ref,
        "terms": terms,
        "evidence": evidence or {},
        "issued_at": int(time.time()) if issued_at is None else int(issued_at),
    })


async def verify_receipt(receipt: Receipt, resolver: KeyResolver, require_countersignature: bool = True) -> None:
    """Raise ReceiptError unless every signature is valid and from the right party."""
    body = receipt.body
    for f in ("type", "issuer", "counterparty", "order_id", "issued_at"):
        if f not in body:
            raise ReceiptError("RECEIPT_MALFORMED", f"missing {f}")
    expected = [("issuer", receipt.issuer)]
    if require_countersignature:
        expected.append(("counterparty", receipt.counterparty))
    if len(receipt.signatures) < len(expected):
        raise ReceiptError("RECEIPT_UNSIGNED", f"needs {len(expected)} signature(s), has {len(receipt.signatures)}")

    for (role, signer), sig in zip(expected, receipt.signatures, strict=False):
        if sig.get("role") != role or sig.get("signer") != signer:
            raise ReceiptError("RECEIPT_WRONG_SIGNER", f"{role} signature must come from {signer}")
        key = await resolver.resolve(signer, sig["key_id"])
        if key is None:
            raise ReceiptError("RECEIPT_UNKNOWN_KEY", f"{signer} has no key {sig['key_id']}")
        # A key revoked *after* signing still proves what was signed while it was valid.
        if not (key.valid_from <= body["issued_at"] <= key.valid_until) or key.status == "INITIATED":
            raise ReceiptError("RECEIPT_KEY_INACTIVE", f"{signer} key {sig['key_id']} not valid at issue time")
        message = (receipt._issue_message() if role == "issuer"
                   else receipt._counter_message(receipt.signatures[0]["sig"]))
        if not verify(key.signing_public_key, message, sig["sig"]):
            raise ReceiptError("RECEIPT_BAD_SIGNATURE", f"{role} signature by {signer} is invalid")
