import re
from pathlib import Path

import pytest
from fastapi import HTTPException

import app.main as main


@pytest.fixture(autouse=True)
def reset_oauth_memory():
    """Prevent OAuth globals from leaking between tests."""
    original_state = main.oauth_state
    original_token = main.oauth_token

    main.oauth_state = None
    main.oauth_token = None

    yield

    main.oauth_state = original_state
    main.oauth_token = original_token


@pytest.mark.parametrize(
    ("stored_state", "returned_state"),
    [
        ("expected-state", None),
        (None, "expected-state"),
        ("expected-state", "wrong-state"),
    ],
)
def test_oauth_callback_rejects_invalid_or_missing_state(
    mocker,
    stored_state,
    returned_state,
):
    main.oauth_state = stored_state

    exchange_mock = mocker.patch.object(
        main,
        "exchange_authorization_code",
    )

    with pytest.raises(HTTPException) as exc_info:
        main.oauth_callback(
            code="test-authorization-code",
            state=returned_state,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Invalid OAuth state"

    # Invalid requests must never reach the token endpoint.
    exchange_mock.assert_not_called()


def test_valid_oauth_callback_returns_no_token(mocker):
    main.oauth_state = "expected-state"

    exchange_mock = mocker.patch.object(
        main,
        "exchange_authorization_code",
        return_value={
            "access_token": "HIGHLY-SENSITIVE-TEST-TOKEN",
            "token_type": "Bearer",
            "expires_in": 3600,
        },
    )

    result = main.oauth_callback(
        code="valid-authorization-code",
        state="expected-state",
    )

    exchange_mock.assert_called_once_with(
        "valid-authorization-code"
    )

    assert result == {
        "message": (
            "OAuth authentication completed successfully"
        ),
        "token_received": True,
        "token_type": "Bearer",
        "expires_in": 3600,
    }

    assert "HIGHLY-SENSITIVE-TEST-TOKEN" not in str(result)

    # The lab currently stores the token only in process memory.
    assert main.oauth_token == "HIGHLY-SENSITIVE-TEST-TOKEN"

    # State is one-time use and must be cleared after success.
    assert main.oauth_state is None


def test_orangehrm_source_does_not_log_http_responses():
    source = Path(
        "app/services/orangehrm.py"
    ).read_text()

    unsafe_logging = re.search(
        r"print\s*\(\s*response\.(text|json)",
        source,
    )

    assert unsafe_logging is None
