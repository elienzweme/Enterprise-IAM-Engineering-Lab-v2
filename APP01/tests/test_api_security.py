
import pytest

from fastapi import HTTPException

from app import security


def clear_api_keys(monkeypatch):
    for name in security.API_KEY_ENV_NAMES:
        monkeypatch.delenv(
            name,
            raising=False,
        )


def test_valid_viewer_key_authenticates(monkeypatch):
    clear_api_keys(monkeypatch)

    monkeypatch.setenv(
        "IAM_VIEWER_API_KEY",
        "unit-test-viewer-key",
    )

    principal = security.authenticate_api_key(
        "unit-test-viewer-key"
    )

    assert principal.subject == "iam.viewer"
    assert principal.roles == frozenset(
        {"iam.viewer"}
    )


def test_invalid_key_is_rejected(monkeypatch):
    clear_api_keys(monkeypatch)

    monkeypatch.setenv(
        "IAM_VIEWER_API_KEY",
        "correct-unit-test-key",
    )

    with pytest.raises(
        HTTPException,
    ) as error:
        security.authenticate_api_key(
            "incorrect-unit-test-key"
        )

    assert error.value.status_code == 401
    assert error.value.detail == "Invalid API key."


def test_missing_configuration_is_rejected(
    monkeypatch,
):
    clear_api_keys(monkeypatch)

    with pytest.raises(
        HTTPException,
    ) as error:
        security.authenticate_api_key(
            "any-key"
        )

    assert error.value.status_code == 503


def test_role_authorization(monkeypatch):
    clear_api_keys(monkeypatch)

    viewer = security.ApiPrincipal(
        subject="iam.viewer",
        roles=frozenset(
            {"iam.viewer"}
        ),
    )

    admin = security.ApiPrincipal(
        subject="iam.admin",
        roles=frozenset(
            {"iam.admin"}
        ),
    )

    require_provisioner = security.require_roles(
        "iam.provisioner"
    )

    with pytest.raises(
        HTTPException,
    ) as error:
        require_provisioner(
            principal=viewer
        )

    assert error.value.status_code == 403

    result = require_provisioner(
        principal=admin
    )

    assert result.subject == "iam.admin"
