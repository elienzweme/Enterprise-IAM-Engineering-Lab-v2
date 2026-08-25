
from datetime import datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.models import CredentialDelivery, IdentityRequest
from app.services.credential_delivery_service import (
    CredentialDeliveryUnavailable,
    create_credential_delivery,
    redeem_credential,
)


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setenv(
        "CREDENTIAL_ENCRYPTION_KEY",
        Fernet.generate_key().decode(),
    )
    monkeypatch.setenv(
        "CREDENTIAL_DELIVERY_TTL_MINUTES",
        "30",
    )

    engine = create_engine(
        "sqlite+pysqlite:///:memory:"
    )
    Base.metadata.create_all(engine)

    session_factory = sessionmaker(
        bind=engine,
        expire_on_commit=False,
    )
    session = session_factory()

    session.add(
        IdentityRequest(
            request_id="JOINER-TEST-001",
            employee_id="TEST-001",
            action="JOINER",
            status="Approved",
            requested_by="pytest",
        )
    )
    session.commit()

    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def create_delivery(db):
    return create_credential_delivery(
        db=db,
        request_id="JOINER-TEST-001",
        employee_id="TEST-001",
        plaintext_password="UnitTest-Temporary-Password!",
    )


def test_password_is_encrypted_and_token_is_hashed(db):
    result = create_delivery(db)
    db.commit()

    row = db.query(CredentialDelivery).one()

    assert row.encrypted_password
    assert "UnitTest-Temporary-Password!" not in row.encrypted_password
    assert row.token_hash
    assert row.token_hash != result["retrieval_token"]
    assert len(row.token_hash) == 64


def test_credential_can_only_be_retrieved_once(db):
    created = create_delivery(db)
    db.commit()

    result = redeem_credential(
        db=db,
        retrieval_token=created["retrieval_token"],
    )
    db.commit()

    assert (
        result["temporary_password"]
        == "UnitTest-Temporary-Password!"
    )

    row = db.query(CredentialDelivery).one()
    assert row.retrieved_at is not None
    assert row.encrypted_password is None

    with pytest.raises(CredentialDeliveryUnavailable):
        redeem_credential(
            db=db,
            retrieval_token=created["retrieval_token"],
        )


def test_expired_credential_is_rejected(db):
    created = create_delivery(db)
    db.commit()

    row = db.query(CredentialDelivery).one()
    row.expires_at = datetime.utcnow() - timedelta(minutes=1)
    db.commit()

    with pytest.raises(CredentialDeliveryUnavailable):
        redeem_credential(
            db=db,
            retrieval_token=created["retrieval_token"],
        )


def test_new_delivery_invalidates_previous_delivery(db):
    first = create_delivery(db)
    db.commit()

    second = create_delivery(db)
    db.commit()

    assert first["retrieval_token"] != second["retrieval_token"]

    with pytest.raises(CredentialDeliveryUnavailable):
        redeem_credential(
            db=db,
            retrieval_token=first["retrieval_token"],
        )

    result = redeem_credential(
        db=db,
        retrieval_token=second["retrieval_token"],
    )

    assert (
        result["temporary_password"]
        == "UnitTest-Temporary-Password!"
    )
