
from types import SimpleNamespace

import pytest

from app.services import employee_sync
from app.services import provisioning_service as ps


DISABLED_OU = (
    "OU=Disabled Users,DC=Corp,DC=local"
)

ACCOUNTING_GROUP = (
    "CN=Accounting Group,OU=Domain Groups,"
    "DC=Corp,DC=local"
)


def test_no_change_request_completes(monkeypatch):
    request = SimpleNamespace(
        request_id="MOVER-test-no-change",
        employee_id="TEST-CONTROL",
        action="MOVER",
        status="Approved",
        approved_by="iam.admin",
        completed_at=None,
    )

    employee = SimpleNamespace(
        employee_id="TEST-CONTROL",
    )

    ad_user = {
        "distinguished_name": (
            "CN=Test Control,"
            "OU=Accounting,OU=Departments,"
            "DC=Corp,DC=local"
        ),
        "enabled": True,
        "manager": None,
        "groups": [ACCOUNTING_GROUP],
    }

    plan = {
        "operation": "UPDATE_AD_USER",
        "current_ad_state": ad_user,
        "ready_for_ad_write": False,
        "execution_enabled": True,
    }

    class FakeDb:
        def commit(self):
            return None

        def refresh(self, value):
            return None

    audit_events = []

    monkeypatch.setattr(
        ps,
        "get_identity_request",
        lambda db, request_id: request,
    )

    monkeypatch.setattr(
        ps,
        "validate_request_for_provisioning",
        lambda request: None,
    )

    monkeypatch.setattr(
        ps,
        "get_employee",
        lambda db, employee_id: employee,
    )

    monkeypatch.setattr(
        ps,
        "get_user_by_employee_id",
        lambda employee_id: ad_user,
    )

    monkeypatch.setattr(
        ps,
        "prepare_mover",
        lambda employee, ad_user: plan,
    )

    monkeypatch.setattr(
        ps,
        "create_audit_event",
        lambda **kwargs: audit_events.append(kwargs),
    )

    result = ps.execute_identity_request(
        request_id=request.request_id,
        db=FakeDb(),
    )

    assert result["request_status"] == "Completed"
    assert result["ad_write_executed"] is False
    assert request.status == "Completed"
    assert request.completed_at is not None

    assert len(audit_events) == 1
    assert (
        audit_events[0]["event_type"]
        == "PROVISIONING_NO_CHANGE"
    )
    assert audit_events[0]["result"] == "SUCCESS"


def test_failed_ldap_operation_is_not_hidden(
    monkeypatch,
):
    employee = SimpleNamespace(
        employee_id="TEST-LDAP-FAILURE",
    )

    plan = {
        "target_ou": DISABLED_OU,
        "groups_to_remove": [ACCOUNTING_GROUP],
        "planned_operations": {
            "disable_account": True,
            "remove_groups": True,
            "clear_manager": False,
            "move_user": False,
        },
    }

    monkeypatch.setattr(
        ps,
        "disable_ad_user",
        lambda employee_id: {
            "success": True,
            "enabled": False,
        },
    )

    def failed_group_removal(
        employee_id,
        group_dn,
    ):
        raise RuntimeError(
            "simulated LDAP group failure"
        )

    monkeypatch.setattr(
        ps,
        "remove_user_from_group",
        failed_group_removal,
    )

    with pytest.raises(
        RuntimeError,
        match="simulated LDAP group failure",
    ):
        ps.execute_leaver(
            employee,
            plan,
        )


def test_duplicate_pending_request_is_prevented():
    class FakeQuery:
        def filter(self, *conditions):
            return self

        def first(self):
            return object()

    class FakeDb:
        def query(self, model):
            return FakeQuery()

        def add(self, value):
            raise AssertionError(
                "Duplicate Pending request was created."
            )

    request = employee_sync.create_identity_request(
        db=FakeDb(),
        employee_id="TEST-DUPLICATE",
        action="LEAVER",
    )

    assert request is None
