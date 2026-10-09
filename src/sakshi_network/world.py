"""The demo network: who exists, where they live, and how they behave.

All names are fictional. Keys are derived from NETWORK_SEED, so every
container in the Docker setup agrees on them without a key-exchange step.
That is a demo convenience: real participants generate keys privately and
only ever publish the public half through the registry.
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass

from .bpp import Seller
from .common import Participant
from .issuer import make_gstin

ITEM_POOL = [
    ("rice-5kg", "Sona Masoori Rice 5kg", 380), ("atta-5kg", "Whole Wheat Atta 5kg", 240),
    ("toor-dal-1kg", "Toor Dal 1kg", 165), ("milk-1l", "Toned Milk 1L", 54), ("eggs-12", "Eggs (12)", 84),
    ("oil-1l", "Sunflower Oil 1L", 145), ("sugar-1kg", "Sugar 1kg", 46), ("tea-500g", "Assam Tea 500g", 240),
    ("onion-1kg", "Onions 1kg", 38), ("tomato-1kg", "Tomatoes 1kg", 32), ("ghee-500ml", "Cow Ghee 500ml", 310),
    ("salt-1kg", "Iodised Salt 1kg", 24), ("paneer-200g", "Fresh Paneer 200g", 90), ("bread", "Brown Bread", 45),
]
QUERIES = ["rice", "atta", "dal", "milk", "eggs", "oil", "sugar", "tea", "onion", "tomato", "ghee", "salt",
           "paneer", "bread"]

# (seller app, seller id, display name, profile, promised delivery seconds at demo scale)
SELLERS = [
    ("kirana", "fresh-basket", "Fresh Basket", "reliable", 30),
    ("kirana", "annapurna-stores", "Annapurna Stores", "slow", 30),
    ("kirana", "metro-mart", "Metro Mart", "flaky", 25),
    ("bazaar", "green-valley", "Green Valley Organics", "reliable", 35),
    ("bazaar", "quickmart-express", "QuickMart Express", "ghost", 20),
    ("bazaar", "deal-dhamaka", "Deal Dhamaka", "bait", 30),
    ("local", "shree-ganesh", "Shree Ganesh Provisions", "reliable", 40),
    ("local", "star-traders", "Star Traders", "booster", 30),
    ("local", "cheap-n-best", "Cheap n Best", "forged", 30),
]
SELLER_APPS = {"kirana": "kirana-connect.in", "bazaar": "bazaar-hub.in", "local": "local-link.in"}


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class Topology:
    seed: str
    admin_token: str
    public_url: str

    @classmethod
    def from_env(cls) -> Topology:
        return cls(env("NETWORK_SEED", "sakshi-demo-network"), env("ADMIN_TOKEN", "demo-admin-token"),
                   env("PUBLIC_URL", "http://localhost:8000").rstrip("/"))

    def host(self, role: str) -> str:
        """Base host of a role. Defaults to PUBLIC_URL (everything in one process)."""
        return env(f"{role.upper()}_HOST", self.public_url).rstrip("/")

    def url(self, role: str, name: str = "") -> str:
        paths = {"registry": "/registry", "gateway": "/gateway", "ledger": "/ledger", "issuer": "/issuer",
                 "bap": "/bap", "bpp": f"/bpp/{name}", "console": "/console", "attackers": f"/attackers/{name}"}
        host_role = "bpp_" + name if role == "bpp" else role
        return self.host(host_role) + paths[role]

    # -------------------------------------------------------------- identities
    def p(self, subscriber_id: str, type_: str, url: str, ukid: str = "k1") -> Participant:
        return Participant.derive(subscriber_id, type_, url, self.seed, ukid)

    @property
    def registry(self) -> Participant:
        return self.p("registry.sakshi.network", "REGISTRY", self.url("registry"))

    @property
    def gateway(self) -> Participant:
        return self.p("gateway.sakshi.network", "BG", self.url("gateway"))

    @property
    def ledger(self) -> Participant:
        return self.p("witness.sakshi.network", "LEDGER", self.url("ledger"))

    @property
    def issuer(self) -> Participant:
        return self.p("gst-authority.sakshi.network", "ISSUER", self.url("issuer"))

    @property
    def bap(self) -> Participant:
        return self.p("paybuddy.app", "BAP", self.url("bap"))

    def bpp(self, name: str) -> Participant:
        return self.p(SELLER_APPS[name], "BPP", self.url("bpp", name))

    # Participants used by the attack lab.
    @property
    def rival_bap(self) -> Participant:
        """A legitimate, registered buyer app that will try to impersonate PayBuddy."""
        return self.p("quickbuy.app", "BAP", self.url("attackers", "quickbuy"))

    def leaky_bap(self, ukid: str = "k1") -> Participant:
        """A buyer app whose old key k1 leaked: rotated to k2, then k1 revoked."""
        return self.p("leakyshop.app", "BAP", self.url("attackers", "leakyshop"), ukid)

    @property
    def mallory(self) -> Participant:
        return self.p("mallory.evil", "BAP", "https://mallory.evil")

    def approved(self) -> dict[str, str]:
        """Operator-approved participants and their endpoints."""
        ps = [self.gateway, self.ledger, self.issuer, self.bap, self.rival_bap, self.leaky_bap()]
        ps += [self.bpp(n) for n in SELLER_APPS]
        return {p.subscriber_id: p.base_url for p in ps}


def build_sellers(app_name: str, seed: str) -> list[Seller]:
    rng = random.Random(f"{seed}|{app_name}")
    sellers = []
    for i, (app, sid, name, profile, promise) in enumerate(SELLERS):
        if app != app_name:
            continue
        picks = rng.sample(ITEM_POOL, 8)
        factor = 0.92 + 0.16 * rng.random()
        items = [{"id": f"{sid}:{iid}", "name": nm, "price": f"{round(base * factor * (0.95 + 0.1 * rng.random()))}.00"}
                 for iid, nm, base in picks]
        letters, digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789"
        # PAN: 3 letters, entity type ("C" = company), first letter of name, 4 digits, check letter
        pan = ("".join(rng.choice(letters) for _ in range(3)) + "C" + name[0].upper()
               + "".join(rng.choice(digits) for _ in range(4)) + rng.choice(letters))
        sellers.append(Seller(sid, name, profile, items, make_gstin(f"{29 + i % 3}", pan), promise))
    return sellers
