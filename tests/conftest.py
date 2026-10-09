from __future__ import annotations

import time

import pytest

from sakshi.auth import KeyRecord
from sakshi.client import StaticResolver
from sakshi.crypto import KeyPair


class Party:
    def __init__(self, name: str, ukid: str = "k1") -> None:
        self.id = name
        self.ukid = ukid
        self.keys = KeyPair.from_seed(f"{name}|{ukid}".encode())

    def record(self, status: str = "SUBSCRIBED", valid_from: float | None = None, valid_until: float | None = None,
               type_: str = "BAP") -> KeyRecord:
        now = time.time()
        return KeyRecord(self.id, self.ukid, self.keys.signing_public,
                         now - 3600 if valid_from is None else valid_from,
                         now + 3600 if valid_until is None else valid_until, status, type_)


@pytest.fixture
def buyer() -> Party:
    return Party("buyer.app")


@pytest.fixture
def seller() -> Party:
    return Party("seller.app")


@pytest.fixture
def resolver(buyer, seller) -> StaticResolver:
    return StaticResolver([buyer.record(), seller.record(type_="BPP")])
