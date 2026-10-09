import time

import pytest

from sakshi.canonical import canonical_json
from sakshi.client import StaticResolver
from sakshi.credentials import (
    CredentialError,
    issue_credential,
    sign_status_list,
    verify_credential,
    verify_status_list,
)
from sakshi.receipts import Receipt, ReceiptError, new_receipt, verify_receipt
from tests.conftest import Party


def contract(seller, buyer, price="499.00", **kw):
    return new_receipt("ORDER_CONTRACT", seller.id, buyer.id, "txn-1", "order-1", "shop-1", "buyer-ref",
                       {"price": {"currency": "INR", "value": price}, "promised_delivery_by": int(time.time()) + 600},
                       **kw)


def signed(seller, buyer, **kw):
    r = contract(seller, buyer, **kw)
    r.sign_as_issuer(seller.ukid, seller.keys.signing_private)
    r.countersign(buyer.ukid, buyer.keys.signing_private)
    return r


# -------------------------------------------------------------- canonical json
def test_canonical_json_is_order_independent():
    assert canonical_json({"b": 1, "a": [1, {"d": "x", "c": None}]}) == canonical_json({"a": [1, {"c": None, "d": "x"}], "b": 1})
    assert canonical_json({"name": "चावल"}) == '{"name":"चावल"}'.encode()


@pytest.mark.parametrize("bad", [{"price": 4.99}, {"x": [1.0]}, {1: "a"}, {"s": {1, 2}}])
def test_canonical_json_rejects_unsafe_values(bad):
    with pytest.raises(TypeError):
        canonical_json(bad)


# -------------------------------------------------------------------- receipts
async def test_countersigned_receipt_verifies(seller, buyer, resolver):
    r = signed(seller, buyer)
    await verify_receipt(r, resolver)
    again = Receipt.from_dict(r.to_dict())                  # survives serialisation
    assert again.receipt_id == r.receipt_id
    await verify_receipt(again, resolver)


async def test_any_change_breaks_the_receipt(seller, buyer, resolver):
    r = signed(seller, buyer)
    r.body["terms"]["price"]["value"] = "1.00"
    with pytest.raises(ReceiptError) as e:
        await verify_receipt(r, resolver)
    assert e.value.code == "RECEIPT_BAD_SIGNATURE"


async def test_missing_countersignature(seller, buyer, resolver):
    r = contract(seller, buyer).sign_as_issuer(seller.ukid, seller.keys.signing_private)
    await verify_receipt(r, resolver, require_countersignature=False)       # binds the issuer already
    with pytest.raises(ReceiptError) as e:
        await verify_receipt(r, resolver)
    assert e.value.code == "RECEIPT_UNSIGNED"


async def test_wrong_party_cannot_sign(seller, buyer, resolver):
    r = contract(seller, buyer)
    r.signatures.append({"role": "issuer", "signer": buyer.id, "key_id": "k1",
                         "sig": "x"})
    with pytest.raises(ReceiptError) as e:
        await verify_receipt(r, resolver, require_countersignature=False)
    assert e.value.code == "RECEIPT_WRONG_SIGNER"


async def test_signatures_are_domain_separated(seller, buyer, resolver):
    """An issuer signature can't be passed off as the counterparty's signature."""
    r = contract(seller, buyer).sign_as_issuer(seller.ukid, seller.keys.signing_private)
    r.signatures.append({"role": "counterparty", "signer": buyer.id, "key_id": "k1",
                         "sig": buyer.keys.sign(b"sakshi/receipt/v1\n" + canonical_json(r.body))})
    with pytest.raises(ReceiptError) as e:
        await verify_receipt(r, resolver)
    assert e.value.code == "RECEIPT_BAD_SIGNATURE"


def test_sign_order_is_enforced(seller, buyer):
    r = contract(seller, buyer)
    with pytest.raises(ReceiptError):
        r.countersign(buyer.ukid, buyer.keys.signing_private)


async def test_receipt_survives_later_key_revocation(seller, buyer):
    """Revoking a key after signing doesn't erase what it signed while valid."""
    r = signed(seller, buyer)
    res = StaticResolver([seller.record("REVOKED"), buyer.record()])
    await verify_receipt(r, res)


# ----------------------------------------------------------------- credentials
@pytest.fixture
def issuer():
    return Party("gst-authority")


@pytest.fixture
def cred_resolver(issuer, seller):
    return StaticResolver([issuer.record(type_="ISSUER"), seller.record(type_="BPP")])


def cred(issuer, subject="seller.app/shop-1", key=None, **kw):
    return issue_credential(issuer.id, "k1", key or issuer.keys.signing_private, subject,
                            {"gstin": "27AAPFU0939F1ZV", "legal_name": "Shop"}, **kw)


async def test_credential_valid(issuer, cred_resolver):
    await verify_credential(cred(issuer), cred_resolver, {issuer.id}, expected_subject="seller.app/shop-1")


@pytest.mark.parametrize("case,code", [
    ("forged", "CRED_BAD_SIGNATURE"), ("subject", "CRED_WRONG_SUBJECT"), ("expired", "CRED_EXPIRED"),
    ("untrusted", "CRED_UNTRUSTED_ISSUER"), ("revoked", "CRED_REVOKED"), ("altered", "CRED_BAD_SIGNATURE"),
])
async def test_credential_failures(case, code, issuer, seller, cred_resolver):
    c = cred(issuer, key=seller.keys.signing_private if case == "forged" else None,
             issued_at=int(time.time()) - 400 * 86400 if case == "expired" else None)
    revoked = {c.credential_id} if case == "revoked" else set()
    if case == "altered":
        c.body["claims"]["legal_name"] = "Someone Else"
    with pytest.raises(CredentialError) as e:
        await verify_credential(c, cred_resolver, set() if case == "untrusted" else {issuer.id},
                                expected_subject="other/shop" if case == "subject" else "seller.app/shop-1",
                                revoked=revoked)
    assert e.value.code == code


async def test_compromised_issuer_key_invalidates_its_credentials(issuer, seller):
    res = StaticResolver([issuer.record("REVOKED", type_="ISSUER")])
    with pytest.raises(CredentialError) as e:
        await verify_credential(cred(issuer), res, {issuer.id})
    assert e.value.code == "CRED_ISSUER_KEY_REVOKED"


def test_status_list_is_signed(issuer, seller):
    status = sign_status_list(issuer.id, "k1", issuer.keys.signing_private, ["b", "a"])
    assert verify_status_list(status, issuer.keys.signing_public) == {"a", "b"}
    status["body"]["revoked"] = []                 # attacker tries to un-revoke
    with pytest.raises(CredentialError):
        verify_status_list(status, issuer.keys.signing_public)
