"""Verifiable seller credentials.

The fake-seller problem: anyone can *claim* "GST registered" in a catalogue.
Here a trusted issuer (in this simulation, a mock GST verification authority
that is itself registered on the network) checks the seller once and signs
a credential. Every buyer app can then verify that credential offline,
without re-running KYC or trusting the seller's word.

This follows the W3C Verifiable Credentials model (issuer, subject, claims,
expiry and revocation) in a deliberately small JSON form.

Revocation: the issuer publishes a *signed* list of revoked credential IDs.
Verifiers check it, so a seller caught cheating loses the badge on every
buyer app at once.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

from .auth import KeyResolver
from .canonical import canonical_json
from .crypto import sign, verify

_CRED_PREFIX = b"sakshi/credential/v1\n"
_STATUS_PREFIX = b"sakshi/credential-status/v1\n"


class CredentialError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass
class Credential:
    body: dict[str, Any]
    proof: dict[str, str]

    @property
    def credential_id(self) -> str:
        return self.body["credential_id"]

    def to_dict(self) -> dict:
        return {"body": self.body, "proof": self.proof}

    @classmethod
    def from_dict(cls, d: dict) -> Credential:
        return cls(body=d["body"], proof=d["proof"])


def issue_credential(issuer: str, key_id: str, private_key_b64: str, subject: str, claims: dict,
                     credential_type: str = "GSTVerification", valid_days: int = 365,
                     issued_at: int | None = None) -> Credential:
    issued = int(time.time()) if issued_at is None else issued_at
    body = {
        "type": credential_type,
        "issuer": issuer,
        "subject": subject,
        "claims": claims,
        "issued_at": issued,
        "expires_at": issued + valid_days * 86400,
    }
    body["credential_id"] = hashlib.sha256(canonical_json(body)).hexdigest()[:32]
    return Credential(body, {"key_id": key_id, "sig": sign(private_key_b64, _CRED_PREFIX + canonical_json(body))})


async def verify_credential(cred: Credential, resolver: KeyResolver, trusted_issuers: set[str],
                            expected_subject: str | None = None, revoked: set[str] | None = None,
                            now: float | None = None) -> None:
    now = time.time() if now is None else now
    b = cred.body
    if b.get("issuer") not in trusted_issuers:
        raise CredentialError("CRED_UNTRUSTED_ISSUER", f"{b.get('issuer')} is not a trusted issuer")
    if expected_subject is not None and b.get("subject") != expected_subject:
        raise CredentialError("CRED_WRONG_SUBJECT", f"issued to {b.get('subject')}, presented by {expected_subject}")
    if not b.get("issued_at", 0) <= now <= b.get("expires_at", 0):
        raise CredentialError("CRED_EXPIRED", "credential is expired or not yet valid")
    key = await resolver.resolve(b["issuer"], cred.proof.get("key_id", ""))
    if key is None or not key.valid_from <= b["issued_at"] <= key.valid_until:
        raise CredentialError("CRED_UNKNOWN_KEY", "issuer key not found or not valid at issue time")
    if key.status == "REVOKED":
        # A revoked issuer key means it may be compromised: nothing it signed can be trusted.
        raise CredentialError("CRED_ISSUER_KEY_REVOKED", "the issuer's signing key has been revoked")
    if not verify(key.signing_public_key, _CRED_PREFIX + canonical_json(b), cred.proof.get("sig", "")):
        raise CredentialError("CRED_BAD_SIGNATURE", "credential signature invalid (forged or altered)")
    if revoked and cred.credential_id in revoked:
        raise CredentialError("CRED_REVOKED", "credential has been revoked by the issuer")


def sign_status_list(issuer: str, key_id: str, private_key_b64: str, revoked_ids: list[str],
                     updated_at: int | None = None) -> dict:
    body = {"issuer": issuer, "revoked": sorted(revoked_ids),
            "updated_at": int(time.time()) if updated_at is None else updated_at}
    return {"body": body, "proof": {"key_id": key_id, "sig": sign(private_key_b64, _STATUS_PREFIX + canonical_json(body))}}


def verify_status_list(status: dict, public_key_b64: str) -> set[str]:
    if not verify(public_key_b64, _STATUS_PREFIX + canonical_json(status["body"]), status["proof"]["sig"]):
        raise CredentialError("CRED_STATUS_BAD_SIGNATURE", "revocation list signature invalid")
    return set(status["body"]["revoked"])
