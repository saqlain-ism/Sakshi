"""Mock GST verification authority: issues signed seller credentials.

In the real world this would be a GST Suvidha Provider or a government API
confirming that a GSTIN is active and belongs to the named business. Here
it validates the GSTIN *format and checksum* (the real mod-36 algorithm)
and keeps a small "verified businesses" list. It then signs a credential
that every buyer app can check offline.
"""

from __future__ import annotations

import hmac
import re

from fastapi import APIRouter, Header, Request

from sakshi.credentials import issue_credential, sign_status_list

from .common import EventBus, Participant, nack
from .registry import on_subscribe_router

_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_GSTIN = re.compile(r"^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$")


def gstin_check_char(first14: str) -> str:
    total = 0
    for i, ch in enumerate(first14):
        product = _CHARS.index(ch) * (2 if i % 2 else 1)
        total += product // 36 + product % 36
    return _CHARS[(36 - total % 36) % 36]


def valid_gstin(gstin: str) -> bool:
    return bool(_GSTIN.match(gstin)) and gstin[14] == gstin_check_char(gstin[:14])


def make_gstin(state: str, pan: str, entity: str = "1") -> str:
    """Build a checksum-valid GSTIN (demo data only)."""
    body = f"{state}{pan}{entity}Z"
    return body + gstin_check_char(body)


class Issuer:
    def __init__(self, me: Participant, bus: EventBus, registry_encryption_public: str, admin_token: str) -> None:
        self.me = me
        self.bus = bus
        self.admin_token = admin_token
        self.issued: dict[str, dict] = {}
        self.revoked: set[str] = set()
        self.router = APIRouter()
        self.router.include_router(on_subscribe_router(lambda: self.me, registry_encryption_public, bus))
        self.router.add_api_route("/credentials/issue", self.issue, methods=["POST"])
        self.router.add_api_route("/credentials/revoke", self.revoke_route, methods=["POST"])
        self.router.add_api_route("/status", self.status, methods=["GET"])

    def _admin(self, token: str) -> bool:
        return bool(self.admin_token) and hmac.compare_digest(token, self.admin_token)

    def issue_for(self, subject: str, gstin: str, legal_name: str) -> dict:
        if not valid_gstin(gstin):
            raise ValueError(f"GSTIN {gstin} fails format/checksum validation")
        cred = issue_credential(self.me.subscriber_id, self.me.unique_key_id, self.me.keys.signing_private, subject,
                                {"gstin": gstin, "legal_name": legal_name, "gst_status": "Active"})
        self.issued[cred.credential_id] = cred.to_dict()
        self.bus.emit("registry", self.me.subscriber_id, f"verified {legal_name} ({gstin}) and issued a credential",
                      "success", subject=subject)
        return cred.to_dict()

    def revoke(self, credential_id: str) -> bool:
        if credential_id not in self.issued:
            return False
        self.revoked.add(credential_id)
        subject = self.issued[credential_id]["body"]["subject"]
        self.bus.emit("registry", self.me.subscriber_id, f"revoked the GST credential of {subject}", "warning")
        return True

    def status_list(self) -> dict:
        return sign_status_list(self.me.subscriber_id, self.me.unique_key_id, self.me.keys.signing_private,
                                sorted(self.revoked))

    async def issue(self, request: Request, x_admin_token: str = Header(default="")):
        if not self._admin(x_admin_token):
            return nack("ADMIN_UNAUTHORISED", "operator token required", 403)
        q = await request.json()
        try:
            return self.issue_for(q["subject"], q["gstin"], q["legal_name"])
        except (KeyError, ValueError) as exc:
            return nack("CRED_REFUSED", str(exc), 400)

    async def revoke_route(self, request: Request, x_admin_token: str = Header(default="")):
        if not self._admin(x_admin_token):
            return nack("ADMIN_UNAUTHORISED", "operator token required", 403)
        return {"revoked": self.revoke((await request.json())["credential_id"])}

    async def status(self):
        return self.status_list()
