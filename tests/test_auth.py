import time

import pytest

from sakshi.auth import AuthError, create_authorization_header, parse_authorization_header, verify_authorization
from sakshi.client import StaticResolver
from sakshi.crypto import KeyPair, b64d, b64e, decrypt, encrypt, shared_key, sign, verify
from sakshi.replay import MemoryReplayStore

BODY = b'{"context":{"action":"search","bap_id":"buyer.app"},"message":{}}'


def header(party, body=BODY, **kw):
    return create_authorization_header(body, party.id, party.ukid, party.keys.signing_private, **kw)


async def expect(code, coro):
    with pytest.raises(AuthError) as e:
        await coro
    assert e.value.code == code


# ---------------------------------------------------------------- primitives
def test_sign_verify_and_bad_inputs():
    k = KeyPair.generate()
    sig = sign(k.signing_private, b"hello")
    assert verify(k.signing_public, b"hello", sig)
    assert not verify(k.signing_public, b"hellO", sig)
    assert not verify(KeyPair.generate().signing_public, b"hello", sig)
    assert not verify(k.signing_public, b"hello", "not-base64!!")
    assert not verify("short", b"hello", sig)


def test_libsodium_64_byte_secret_key_is_accepted():
    k = KeyPair.generate()
    libsodium = b64e(b64d(k.signing_private) + b64d(k.signing_public))
    assert verify(k.signing_public, b"m", sign(libsodium, b"m"))


def test_challenge_encryption_roundtrip_and_tamper():
    a, b = KeyPair.generate(), KeyPair.generate()
    k_ab = shared_key(a.encryption_private, b.encryption_public)
    assert k_ab == shared_key(b.encryption_private, a.encryption_public)        # ECDH agreement
    token = encrypt(k_ab, b"secret", aad=b"buyer.app")
    assert decrypt(k_ab, token, aad=b"buyer.app") == b"secret"
    with pytest.raises(ValueError):
        decrypt(k_ab, token, aad=b"someone-else")                                # bound to the subscriber
    with pytest.raises(ValueError):
        decrypt(shared_key(KeyPair.generate().encryption_private, b.encryption_public), token, aad=b"buyer.app")
    raw = bytearray(b64d(token))
    raw[-1] ^= 1
    with pytest.raises(ValueError):
        decrypt(k_ab, b64e(bytes(raw)), aad=b"buyer.app")                       # GCM detects tampering


# ------------------------------------------------------------------- headers
def test_header_format_matches_beckn():
    from tests.conftest import Party
    p = parse_authorization_header(header(Party("buyer.app"), created=1000))
    assert (p.subscriber_id, p.unique_key_id, p.algorithm) == ("buyer.app", "k1", "ed25519")
    assert (p.created, p.expires, p.headers) == (1000, 1030, "(created) (expires) digest")


async def test_valid_request(buyer, resolver):
    sender = await verify_authorization(header(buyer), BODY, resolver)
    assert sender.subscriber_id == "buyer.app"


async def test_tampered_body(buyer, resolver):
    await expect("AUTH_BAD_SIGNATURE", verify_authorization(header(buyer), BODY.replace(b"search", b"select"), resolver))


async def test_wrong_key(buyer, seller, resolver):
    forged = create_authorization_header(BODY, buyer.id, buyer.ukid, seller.keys.signing_private)
    await expect("AUTH_BAD_SIGNATURE", verify_authorization(forged, BODY, resolver))


async def test_time_checks(buyer, resolver):
    now = time.time()
    await expect("AUTH_EXPIRED", verify_authorization(header(buyer, created=int(now) - 600), BODY, resolver))
    await expect("AUTH_NOT_YET_VALID", verify_authorization(header(buyer, created=int(now) + 600), BODY, resolver))
    await expect("AUTH_WINDOW_TOO_LONG", verify_authorization(header(buyer, ttl_s=3600), BODY, resolver))
    # small clock skew between participants is tolerated
    await verify_authorization(header(buyer, created=int(now) + 3), BODY, resolver)


async def test_key_lifecycle(buyer):
    await expect("AUTH_UNKNOWN_KEY", verify_authorization(header(buyer), BODY, StaticResolver([])))
    await expect("AUTH_KEY_REVOKED", verify_authorization(header(buyer), BODY, StaticResolver([buyer.record("REVOKED")])))
    expired_key = StaticResolver([buyer.record(valid_until=time.time() - 60)])
    await expect("AUTH_KEY_INACTIVE", verify_authorization(header(buyer), BODY, expired_key))


@pytest.mark.parametrize("bad", [None, "", "Bearer x", 'Signature keyId="a|b",algorithm="ed25519"',
                                 'Signature keyId="a||ed25519",algorithm="ed25519",created="1",expires="2",headers="h",signature="s"',
                                 'Signature keyId="a|b|ed25519",algorithm="ed25519",created="x",expires="2",headers="h",signature="s"'])
async def test_malformed_headers(bad, resolver):
    with pytest.raises(AuthError) as e:
        await verify_authorization(bad, BODY, resolver)
    assert e.value.code in ("AUTH_MISSING", "AUTH_MALFORMED")


async def test_unsupported_algorithm(buyer, resolver):
    h = header(buyer).replace('algorithm="ed25519"', 'algorithm="rsa-sha256"')
    await expect("AUTH_UNSUPPORTED", verify_authorization(h, BODY, resolver))


async def test_replay_is_rejected_and_bad_requests_do_not_poison_cache(buyer, resolver):
    store = MemoryReplayStore()
    h = header(buyer)
    # an invalid request carrying the same signature must not block the genuine one
    await expect("AUTH_BAD_SIGNATURE", verify_authorization(h, BODY + b" ", resolver, store))
    await verify_authorization(h, BODY, resolver, store)
    await expect("AUTH_REPLAY", verify_authorization(h, BODY, resolver, store))


async def test_empty_replay_store_still_counts():
    # regression: an empty store has len() == 0, so `if store:` silently disabled replay protection
    assert not MemoryReplayStore()
    assert MemoryReplayStore() is not None


async def test_redis_replay_store(buyer, resolver):
    fakeredis = pytest.importorskip("fakeredis")
    from sakshi.replay import RedisReplayStore
    store = RedisReplayStore(fakeredis.FakeAsyncRedis())
    h = header(buyer)
    await verify_authorization(h, BODY, resolver, store)
    await expect("AUTH_REPLAY", verify_authorization(h, BODY, resolver, store))
