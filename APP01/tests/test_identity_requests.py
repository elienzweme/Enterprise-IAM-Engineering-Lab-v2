from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.services import provisioning_service as ps


def test_no_change_request_completes_without_ad_write(mocker):
    """
    An approved request whose desired AD state is already satisfied
    must complete successfully without executing provisioning.
    """

    request = SimpleNamespace(
        request_id="LEAVER-NOCHANGE-TEST",
        employee_id="T9300",
        action="LEAVER",
        status="Approved",
        approved_by="pytest.admin",
        completed_at=None,
    )

    employee = SimpleNamespace(
        employee_id="T9300",
        employment_status="Terminated",
    )

    final_ad_state = {
        "distinguished_name": (
            "CN=No Change User,"
            "OU=Disabled Users,"
            "DC=Corp,DC=local"
        ),
        "employee_id": "T9300",
        "enabled": False,
        "manager": None,
        "groups": [],
    }

    plan = {
        "operation": "DISABLE_AD_USER",
        "employee_id": "T9300",
        "groups_to_remove": [],
        "clear_manager": False,
        "target_ou": ps.AD_DISABLED_USERS_OU,
        "planned_operations": {
            "disable_account": False,
            "remove_groups": False,
            "clear_manager": False,
            "move_user": False,
        },
        "ready_for_ad_write": False,
        "execution_enabled": True,
    }

    db = MagicMock()

    mocker.patch.object(
        ps,
        "get_identity_request",
        return_value=request,
    )

    validation_mock = mocker.patch.object(
        ps,
        "validate_request_for_provisioning",
    )

    mocker.patch.object(
        ps,
        "get_employee",
        return_value=employee,
    )

    mocker.patch.object(
        ps,
        "get_user_by_employee_id",
        return_value=final_ad_state,
    )

    prepare_mock = mocker.patch.object(
        ps,
        "prepare_leaver",
        return_value=plan,
    )

    execute_mock = mocker.patch.object(
        ps,
        "execute_leaver",
    )

    audit_mock = mocker.patch.object(
        ps,
        "create_audit_event",
    )

    result = ps.execute_identity_request(
        request_id="LEAVER-NOCHANGE-TEST",
        db=db,
    )

    assert result["status"] == "success"
    assert result["request_id"] == "LEAVER-NOCHANGE-TEST"
    assert result["employee_id"] == "T9300"
    assert result["action"] == "LEAVER"
    assert result["request_status"] == "Completed"
    assert result["ad_write_executed"] is False

    assert request.status == "Completed"
    assert isinstance(request.completed_at, datetime)

    validation_mock.assert_called_once_with(request)

    prepare_mock.assert_called_once_with(
        employee=employee,
        ad_user=final_ad_state,
    )

    execute_mock.assert_not_called()

    assert audit_mock.call_count == 1
    audit_kwargs = audit_mock.call_args.kwargs

    assert audit_kwargs["event_type"] == "PROVISIONING_NO_CHANGE"
    assert audit_kwargs["result"] == "SUCCESS"
    assert audit_kwargs["request"] is request

    db.commit.assert_called_once()

def test_failed_request_can_be_retried_successfully(mocker):
    """
    A failed LDAP provisioning attempt must leave the approved request
    retryable. A later successful retry must complete the same request.
    """
    import pytest

    request = SimpleNamespace(
        request_id="LEAVER-RETRY-TEST",
        employee_id="T9301",
        action="LEAVER",
        status="Approved",
        approved_by="pytest.admin",
        completed_at=None,
    )

    employee = SimpleNamespace(
        employee_id="T9301",
        employment_status="Terminated",
    )

    current_ad_state = {
        "distinguished_name": (
            "CN=Retry User,"
            "OU=Accounting,OU=Departments,"
            "DC=Corp,DC=local"
        ),
        "employee_id": "T9301",
        "enabled": True,
        "manager": (
            "CN=Henry Woodward,"
            "OU=Accounting,OU=Departments,"
            "DC=Corp,DC=local"
        ),
        "groups": [
            "CN=Accounting Group,"
            "OU=Domain Groups,"
            "DC=Corp,DC=local"
        ],
    }

    verified_ad_state = {
        **current_ad_state,
        "distinguished_name": (
            "CN=Retry User,"
            "OU=Disabled Users,"
            "DC=Corp,DC=local"
        ),
        "enabled": False,
        "manager": None,
        "groups": [],
    }

    plan = {
        "operation": "DISABLE_AD_USER",
        "employee_id": "T9301",
        "groups_to_remove": current_ad_state["groups"],
        "clear_manager": True,
        "target_ou": ps.AD_DISABLED_USERS_OU,
        "planned_operations": {
            "disable_account": True,
            "remove_groups": True,
            "clear_manager": True,
            "move_user": True,
        },
        "ready_for_ad_write": True,
        "execution_enabled": True,
    }

    successful_execution = {
        "employee_id": "T9301",
        "verified_ad_state": verified_ad_state,
    }

    db = MagicMock()

    mocker.patch.object(
        ps,
        "get_identity_request",
        return_value=request,
    )

    mocker.patch.object(
        ps,
        "get_employee",
        return_value=employee,
    )

    mocker.patch.object(
        ps,
        "get_user_by_employee_id",
        return_value=current_ad_state,
    )

    mocker.patch.object(
        ps,
        "prepare_leaver",
        return_value=plan,
    )

    execute_mock = mocker.patch.object(
        ps,
        "execute_leaver",
        side_effect=[
            RuntimeError("Simulated LDAP failure"),
            successful_execution,
        ],
    )

    audit_mock = mocker.patch.object(
        ps,
        "create_audit_event",
    )

    # First provisioning attempt fails.
    with pytest.raises(
        RuntimeError,
        match="LEAVER provisioning failed",
    ):
        ps.execute_identity_request(
            request_id="LEAVER-RETRY-TEST",
            db=db,
        )

    assert request.status == "Failed"
    assert request.completed_at is None
    db.rollback.assert_called_once()

    # A Failed request with its original approval must remain retryable.
    ps.validate_request_for_provisioning(request)

    # Retry the same request. The second mocked LDAP execution succeeds.
    result = ps.execute_identity_request(
        request_id="LEAVER-RETRY-TEST",
        db=db,
    )

    assert execute_mock.call_count == 2
    assert result["status"] == "success"
    assert result["request_id"] == "LEAVER-RETRY-TEST"
    assert result["request_status"] == "Completed"
    assert result["ad_write_executed"] is True

    assert request.status == "Completed"
    assert isinstance(request.completed_at, datetime)

    event_types = [
        call.kwargs["event_type"]
        for call in audit_mock.call_args_list
    ]

    assert event_types == [
        "PROVISIONING_STARTED",
        "PROVISIONING_FAILED",
        "PROVISIONING_STARTED",
        "PROVISIONING_COMPLETED",
    ]

