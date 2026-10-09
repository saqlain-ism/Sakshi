"""End-to-end tests against the whole network running in one process.

Participants still talk over (in-process) HTTP, so these exercise the real
request signing, routing, verification, registry and ledger code paths.
"""

import asyncio
import json
import os
import time

import httpx
import pytest
import pytest_asyncio

from sakshi.auth import AuthError, KeyRecord, create_authorization_header
from sakshi.client import RegistryResolver
from sakshi.crypto import KeyPair
from sakshi.receipts import new_receipt
from sakshi_network.common import Participant, context
from sakshi_network.registry import subscribe

pytestmark = pytest.mark.asyncio(loop_scope="module")
EXPECTED = {
    "forged_signature": ("BLOCKED", "AUTH_BAD_SIGNATURE"), "tampered_body": ("BLOCKED", "AUTH_BAD_SIGNATURE"),
    "replay": ("BLOCKED", "AUTH_REPLAY"), "expired": ("BLOCKED", "AUTH_EXPIRED"),
    "spoofed_sender": ("BLOCKED", "AUTH_SPOOFED_SENDER"), "fake_gateway": ("BLOCKED", "AUTH_WRONG_ROLE"),
    "leaked_key": ("BLOCKED", "AUTH_KEY_REVOKED"), "rogue_registry": ("BLOCKED", "AUTH_BAD_SIGNATURE"),
    "hijack_registration": ("BLOCKED", "SUBSCRIBE_ROTATION_UNAUTHORISED"),
    "unapproved_join": ("BLOCKED", "SUBSCRIBE_NOT_APPROVED"), "forged_credential": ("BLOCKED", "CRED_BAD_SIGNATURE"),
    "bait_and_switch": ("BLOCKED", "PRICE_MISMATCH"), "deny_promise": ("DISPROVEN", "SIGNATURE_VERIFIED"),
    "backdated_receipt": ("BLOCKED", "LEDGER_STALE"), "silent_edit": ("DETECTED", "INCLUSION_FAILED"),
    "history_rewrite": ("DETECTED", "CONSISTENCY_FAILED"),
}


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def net():
    os.environ.update(SIMULATION="off", TIME_SCALE="0.03", SEARCH_WINDOW_S="0.3", SAKSHI_ROLE="all")
    from sakshi_network.app import create_app
    from sakshi_network.world import Topology
    app = create_app("all")
    async with app.router.lifespan_context(app):
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000",
                                   timeout=30)
        yield client, Topology.from_env()


async def order(client, seller_id=None, query="rice"):
    if seller_id:
        query = ""            # the chosen seller may not stock rice; search the whole catalogue
    return (await client.post("/bap/api/orders", json={"buyer": "test", "query": query, "seller_id": seller_id})).json()


async def test_network_bootstrapped(net):
    client, _ = net
    parts = (await client.get("/registry/participants")).json()
    by_key = {(p["subscriber_id"], p["ukId"]): p["status"] for p in parts}
    assert by_key[("paybuddy.app", "k1")] == "SUBSCRIBED"
    assert by_key[("leakyshop.app", "k1")] == "REVOKED"
    assert by_key[("leakyshop.app", "k2")] == "SUBSCRIBED"
    assert len({p["subscriber_id"] for p in parts}) == 10


async def test_order_end_to_end_and_independent_verification(net):
    client, _ = net
    o = await order(client, "fresh-basket")
    assert o["status"] == "CONFIRMED"
    assert "ORDER_CONTRACT" in o["ledger"]
    for _ in range(50):                                   # delivery arrives asynchronously
        await asyncio.sleep(0.1)
        rows = (await client.get(f"/ledger/orders/{o['order_id']}")).json()
        if len(rows) == 2:
            break
    assert [r["type"] for r in rows] == ["ORDER_CONTRACT", "FULFILMENT"]
    v = (await client.get(f"/console/api/verify/{o['order_id']}")).json()
    assert v["ok"] and len(v["steps"]) == 5


@pytest.mark.parametrize("name", list(EXPECTED))
async def test_attack_lab(net, name):
    client, _ = net
    if name in ("deny_promise", "silent_edit", "history_rewrite"):
        await order(client, "green-valley")
    r = (await client.post(f"/console/api/attacks/{name}")).json()
    assert (r["outcome"], r["code"]) == EXPECTED[name], r


async def test_ledger_is_intact_after_tamper_demos(net):
    client, t = net
    from sakshi_network.common import EventBus
    from sakshi_network.ledger import Auditor
    fresh = Auditor("test-auditor", t.url("ledger"), t.ledger.keys.signing_public, client, EventBus(), sample=50)
    assert await fresh.check()


async def test_spoofed_callback_is_rejected(net):
    client, t = net
    kirana, bazaar, bap = t.bpp("kirana"), t.bpp("bazaar"), t.bap
    ctx = {**context("on_select", bap, "txn-x"), "bpp_id": bazaar.subscriber_id, "bpp_uri": bazaar.base_url}
    body = json.dumps({"context": ctx, "message": {}}).encode()
    auth = create_authorization_header(body, kirana.subscriber_id, "k1", kirana.keys.signing_private)
    r = await client.post("/bap/on_select", content=body, headers={"Authorization": auth, "Content-Type": "application/json"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "AUTH_SPOOFED_SENDER"


async def test_registry_refuses_wrong_url_and_failed_challenge(net):
    client, t = net
    rival = t.rival_bap
    elsewhere = Participant(rival.subscriber_id, "BAP", "https://evil.example", KeyPair.generate(), "k5")
    r = await subscribe(elsewhere, t.url("registry"), client)
    assert r.json()["error"]["code"] == "SUBSCRIBE_URL_MISMATCH"
    # authorised rotation, but the endpoint can't decrypt the challenge for the new key
    wrong = Participant(rival.subscriber_id, "BAP", rival.base_url, KeyPair.generate(), "k6")
    r = await subscribe(wrong, t.url("registry"), client, current=rival)
    assert r.json()["error"]["code"] == "SUBSCRIBE_CHALLENGE_FAILED"


async def test_unsigned_registry_answers_are_refused(net):
    client, t = net
    wrong_pin = KeyRecord(t.registry.subscriber_id, "k1", KeyPair.generate().signing_public, 0, 4e9, "SUBSCRIBED")
    resolver = RegistryResolver(t.url("registry"), wrong_pin, client)
    with pytest.raises(AuthError) as e:
        await resolver.resolve("paybuddy.app", "k1")
    assert e.value.code == "REGISTRY_UNTRUSTED"


async def test_ledger_admission_rules(net):
    client, t = net
    bap, kirana, rival = t.bap, t.bpp("kirana"), t.rival_bap

    async def submit(receipt, signer, age=0):
        body = json.dumps({"receipt": receipt.to_dict()}).encode()
        auth = create_authorization_header(body, signer.subscriber_id, "k1", signer.keys.signing_private,
                                           created=int(time.time()) - age)
        return (await client.post("/ledger/entries", content=body,
                                  headers={"Authorization": auth, "Content-Type": "application/json"})).json()

    def contract(oid):
        return new_receipt("ORDER_CONTRACT", kirana.subscriber_id, bap.subscriber_id, "t", oid, "fresh-basket", "b",
                           {"price": {"currency": "INR", "value": "10.00"}, "promised_delivery_by": int(time.time()) + 60}
                           ).sign_as_issuer("k1", kirana.keys.signing_private)

    assert (await submit(contract("x1"), bap))["error"]["code"] == "RECEIPT_UNSIGNED"
    full = contract("x2").countersign("k1", bap.keys.signing_private)
    assert (await submit(full, rival))["error"]["code"] == "LEDGER_NOT_A_PARTY"
    first = await submit(full, bap, age=3)
    assert (await submit(full, bap, age=3))["error"]["code"] == "AUTH_REPLAY"   # same signed request: replay
    again = await submit(full, bap, age=1)                                       # freshly signed resubmission
    assert again["duplicate"] and again["index"] == first["index"]               # idempotent
    orphan = new_receipt("FULFILMENT", kirana.subscriber_id, bap.subscriber_id, "t", "never-ordered", "fresh-basket",
                         "b", {"delivered_at": int(time.time())})
    orphan.sign_as_issuer("k1", kirana.keys.signing_private).countersign("k1", bap.keys.signing_private)
    assert (await submit(orphan, bap))["error"]["code"] == "LEDGER_INCONSISTENT"


async def test_disputes_flow_for_ghost_seller(net):
    client, t = net
    o = await order(client, "quickmart-express")                 # takes orders, never delivers
    assert o["status"] == "CONFIRMED"
    signer = t.bap
    body = json.dumps({"order_id": o["order_id"], "claim": "NOT_DELIVERED", "evidence": []}).encode()

    async def file():
        auth = create_authorization_header(body, signer.subscriber_id, "k1", signer.keys.signing_private)
        return (await client.post("/ledger/disputes", content=body,
                                  headers={"Authorization": auth, "Content-Type": "application/json"})).json()
    early = await file()
    assert early["verdict"]["outcome"] == "REJECTED"                   # promise hasn't expired yet
    rep = (await client.get("/ledger/reputation")).json()
    assert rep["computed_over"]["tree_size"] >= 1


async def test_reputation_is_recomputable_from_the_log(net):
    client, _ = net
    from sakshi.orders import LedgerEntry
    from sakshi.reputation import compute_reputation
    snap = (await client.get("/ledger/reputation")).json()
    basis = snap["computed_over"]
    rows = (await client.get("/ledger/entries", params={"start": 0, "end": basis["tree_size"]})).json()
    mine = compute_reputation([LedgerEntry(r["index"], r["logged_at"], r["receipt"]) for r in rows], as_of=basis["as_of"])
    assert {k: v.to_dict() for k, v in mine.items()} == snap["sellers"]
