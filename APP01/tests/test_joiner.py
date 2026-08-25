
from types import SimpleNamespace

import pytest

from app.services import provisioning_service as ps


ACCOUNTING_OU = (
    "OU=Accounting,OU=Departments,DC=Corp,DC=local"
)

ACCOUNTING_GROUP = (
    "CN=Accounting Group,OU=Domain Groups,"
    "DC=Corp,DC=local"
)

MANAGER_DN = (
    "CN=Henry Woodward,OU=Accounting,"
    "OU=Departments,DC=Corp,DC=local"
)


def employee(**overrides):
    values = {
        "employee_id": "TEST-JOINER",
        "first_name": "Test",
        "last_name": "Joiner",
        "email": None,
        "department": "Accounting",
        "job_title": "Account Payable Analyst",
        "manager": "Henry Woodward",
        "manager_employee_id": "0008",
        "employment_status": "Full-Time Permanent",
    }

    values.update(overrides)
    return SimpleNamespace(**values)


def accounting_mapping():
    return {
        "department": "Accounting",
        "ou": ACCOUNTING_OU,
        "groups": ["Accounting Group"],
        "group_dns": [ACCOUNTING_GROUP],
    }


def test_prepare_joiner_resolves_manager(monkeypatch):
    monkeypatch.setattr(
        ps,
        "get_employee_identity_mapping",
        lambda employee: accounting_mapping(),
    )

    monkeypatch.setattr(
        ps,
        "get_user_by_employee_id",
        lambda employee_id: {
            "distinguished_name": MANAGER_DN,
        },
    )

    plan = ps.prepare_joiner(
        employee(),
        None,
    )

    assert plan["manager_change"] == {
        "old": None,
        "new": MANAGER_DN,
        "manager_employee_id": "0008",
        "assignment_required": True,
    }


def test_prepare_joiner_rejects_missing_manager(monkeypatch):
    monkeypatch.setattr(
        ps,
        "get_employee_identity_mapping",
        lambda employee: accounting_mapping(),
    )

    monkeypatch.setattr(
        ps,
        "get_user_by_employee_id",
        lambda employee_id: None,
    )

    with pytest.raises(
        ValueError,
        match="does not exist in Active Directory",
    ):
        ps.prepare_joiner(
            employee(),
            None,
        )


def test_prepare_partial_joiner_recovery(monkeypatch):
    monkeypatch.setattr(
        ps,
        "get_employee_identity_mapping",
        lambda employee: accounting_mapping(),
    )

    monkeypatch.setattr(
        ps,
        "get_user_by_employee_id",
        lambda employee_id: {
            "distinguished_name": MANAGER_DN,
        },
    )

    existing_user = {
        "employee_id": "TEST-JOINER",
        "distinguished_name": (
            "CN=Test Joiner," + ACCOUNTING_OU
        ),
        "enabled": False,
        "manager": None,
        "groups": [],
    }

    plan = ps.prepare_joiner(
        employee(),
        existing_user,
    )

    assert (
        plan["recovery"]["partial_joiner"]
        is True
    )

    assert (
        plan["recovery"]["existing_ad_user"]
        == existing_user
    )

    assert (
        plan["manager_change"]["assignment_required"]
        is True
    )


def test_execute_joiner_assigns_manager(monkeypatch):
    employee_record = employee()
    state = {"user": None}
    operations = []

    plan = {
        "operation": "CREATE_AD_USER",
        "employee_id": employee_record.employee_id,
        "desired_state": vars(employee_record),
        "identity_mapping": {
            "target_ou": ACCOUNTING_OU,
            "birthright_groups": [
                "Accounting Group",
            ],
            "birthright_group_dns": [
                ACCOUNTING_GROUP,
            ],
        },
        "manager_change": {
            "old": None,
            "new": MANAGER_DN,
            "manager_employee_id": "0008",
            "assignment_required": True,
        },
        "recovery": {
            "partial_joiner": False,
            "existing_ad_user": None,
        },
    }

    def get_user_by_employee_id(employee_id):
        if state["user"] is None:
            return None

        return dict(state["user"])

    def create_ad_user(**kwargs):
        operations.append("create_account")

        state["user"] = {
            "distinguished_name": (
                "CN=Test Joiner," + ACCOUNTING_OU
            ),
            "employee_id": employee_record.employee_id,
            "enabled": False,
            "manager": None,
            "groups": [],
        }

        return {"success": True}

    def add_user_to_group(employee_id, group_dn):
        operations.append("add_group")
        state["user"]["groups"].append(group_dn)

        return {
            "success": True,
            "group_dn": group_dn,
        }

    def set_ad_manager(
        employee_id,
        manager_employee_id,
    ):
        operations.append("assign_manager")
        state["user"]["manager"] = MANAGER_DN

        return {
            "success": True,
            "manager_dn": MANAGER_DN,
        }

    def set_ad_password(**kwargs):
        operations.append("set_password")
        return {"success": True}

    def require_password_change_at_next_logon(
        **kwargs,
    ):
        operations.append("require_password_change")
        return {"success": True}

    def enable_ad_user(employee_id):
        operations.append("enable_account")
        state["user"]["enabled"] = True

        return {
            "success": True,
            "enabled": True,
        }

    monkeypatch.setattr(
        ps,
        "get_user_by_employee_id",
        get_user_by_employee_id,
    )
    monkeypatch.setattr(
        ps,
        "create_ad_user",
        create_ad_user,
    )
    monkeypatch.setattr(
        ps,
        "add_user_to_group",
        add_user_to_group,
    )
    monkeypatch.setattr(
        ps,
        "set_ad_manager",
        set_ad_manager,
    )
    monkeypatch.setattr(
        ps,
        "generate_temporary_password",
        lambda: "Valid-Temporary9!",
    )
    monkeypatch.setattr(
        ps,
        "set_ad_password",
        set_ad_password,
    )
    monkeypatch.setattr(
        ps,
        "require_password_change_at_next_logon",
        require_password_change_at_next_logon,
    )
    monkeypatch.setattr(
        ps,
        "enable_ad_user",
        enable_ad_user,
    )

    result = ps.execute_joiner(
        employee_record,
        plan,
    )

    verified = result["verified_ad_state"]

    assert verified["enabled"] is True
    assert verified["manager"] == MANAGER_DN
    assert verified["groups"] == [
        ACCOUNTING_GROUP,
    ]

    assert operations == [
        "create_account",
        "add_group",
        "assign_manager",
        "set_password",
        "require_password_change",
        "enable_account",
    ]
