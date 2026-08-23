from unittest.mock import MagicMock

from app.services import employee_sync as es


def test_duplicate_pending_request_is_not_created(mocker):
    """
    HR synchronization must not create another request when the same
    employee already has a Pending request for the same lifecycle action.
    """

    db = MagicMock()

    pending_mock = mocker.patch.object(
        es,
        "pending_request_exists",
        return_value=True,
    )

    request_id_mock = mocker.patch.object(
        es,
        "generate_request_id",
    )

    result = es.create_identity_request(
        db=db,
        employee_id="T9400",
        action="LEAVER",
    )

    assert result is None

    pending_mock.assert_called_once_with(
        db,
        "T9400",
        "LEAVER",
    )

    request_id_mock.assert_not_called()
    db.add.assert_not_called()
