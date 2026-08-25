from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
import secrets
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from app.models.models import CredentialDelivery


class CredentialDeliveryUnavailable(ValueError):
    """The credential is missing, expired, or already retrieved."""


def _utcnow() -> datetime:
    """Return a naive UTC value compatible with existing database columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _cipher() -> Fernet:
    key = os.getenv("CREDENTIAL_ENCRYPTION_KEY")

    if not key:
        raise RuntimeError(
            "CREDENTIAL_ENCRYPTION_KEY is not configured."
        )

    try:
        return Fernet(key.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "CREDENTIAL_ENCRYPTION_KEY is invalid."
        ) from exc


def _ttl_minutes() -> int:
    raw_value = os.getenv(
        "CREDENTIAL_DELIVERY_TTL_MINUTES",
        "30",
    )

    try:
        ttl = int(raw_value)
    except ValueError as exc:
        raise RuntimeError(
            "CREDENTIAL_DELIVERY_TTL_MINUTES must be an integer."
        ) from exc

    if ttl < 1 or ttl > 1440:
        raise RuntimeError(
            "Credential delivery TTL must be between 1 and 1440 minutes."
        )

    return ttl


def create_credential_delivery(
    db: Session,
    *,
    request_id: str,
    employee_id: str,
    plaintext_password: str,
) -> dict:
    """
    Encrypt a temporary password and generate a one-time bearer token.

    The plaintext password and usable token are never stored in the database.
    The caller must never write retrieval_token to logs or audit events.
    """

    if not request_id.strip():
        raise ValueError("request_id is required.")

    if not employee_id.strip():
        raise ValueError("employee_id is required.")

    if not plaintext_password:
        raise ValueError("plaintext_password is required.")

    now = _utcnow()

    # Invalidate any previous unretrieved delivery for this request.
    previous_deliveries = (
        db.query(CredentialDelivery)
        .filter(
            CredentialDelivery.request_id == request_id,
            CredentialDelivery.retrieved_at.is_(None),
            CredentialDelivery.encrypted_password.is_not(None),
        )
        .all()
    )

    for previous in previous_deliveries:
        previous.encrypted_password = None
        previous.expires_at = now

    retrieval_token = secrets.token_urlsafe(32)

    delivery = CredentialDelivery(
        delivery_id=f"CRED-{uuid4().hex[:12]}",
        request_id=request_id,
        employee_id=employee_id,
        token_hash=_token_hash(retrieval_token),
        encrypted_password=(
            _cipher()
            .encrypt(plaintext_password.encode("utf-8"))
            .decode("utf-8")
        ),
        expires_at=now + timedelta(minutes=_ttl_minutes()),
        created_at=now,
    )

    db.add(delivery)
    db.flush()

    return {
        "delivery_id": delivery.delivery_id,
        "retrieval_token": retrieval_token,
        "employee_id": employee_id,
        "expires_at": delivery.expires_at.isoformat(),
    }


def redeem_credential(
    db: Session,
    *,
    retrieval_token: str,
) -> dict:
    """
    Redeem and destroy an encrypted credential.

    All invalid, expired, reused, or corrupted tokens return the same error.
    The caller controls the final database commit or rollback.
    """

    if not retrieval_token:
        raise CredentialDeliveryUnavailable(
            "Credential is unavailable."
        )

    now = _utcnow()

    delivery = (
        db.query(CredentialDelivery)
        .filter(
            CredentialDelivery.token_hash
            == _token_hash(retrieval_token)
        )
        .with_for_update()
        .one_or_none()
    )

    if (
        delivery is None
        or delivery.retrieved_at is not None
        or delivery.encrypted_password is None
        or delivery.expires_at <= now
    ):
        raise CredentialDeliveryUnavailable(
            "Credential is unavailable."
        )

    try:
        plaintext_password = (
            _cipher()
            .decrypt(delivery.encrypted_password.encode("utf-8"))
            .decode("utf-8")
        )
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise CredentialDeliveryUnavailable(
            "Credential is unavailable."
        ) from exc

    # Destroy the ciphertext before returning the one-time value.
    delivery.encrypted_password = None
    delivery.retrieved_at = now
    db.flush()

    return {
        "delivery_id": delivery.delivery_id,
        "employee_id": delivery.employee_id,
        "temporary_password": plaintext_password,
        "retrieved_at": now.isoformat(),
    }
