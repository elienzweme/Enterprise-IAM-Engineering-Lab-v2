
from types import SimpleNamespace

from app.services import provisioning_service as ps


ACCOUNTING_OU = (
    "OU=Accounting,OU=Departments,DC=Corp,DC=local"
)

FINANCE_OU = (
    "OU=Finance,OU=Departments,DC=Corp,DC=local"
)

ACCOUNTING_GROUP = (
    "CN=Accounting Group,OU=Domain Groups,"
    "DC=Corp,DC=local"
)

FINANCE_GROUP = (
    "CN=Finance Group,OU=Domain Groups,"
    "DC=Corp,DC=local"
)

MANAGER_DN = (
    "CN=Henry Woodward,OU=Accounting,"
    "OU=Departments,DC=Corp,DC=local"
)


def employee(**overrides):
    values = {
        "employee_id": "TEST-MOVER",
        "first_name": "Test",
        "last_name": "Mover",
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


def accounting_ad_user():
    return {
        "distinguished_name": (
            "CN=Test Mover," + ACCOUNTING_OU
        ),
        "sam_account_name": "test.mover",
        "department": "Accounting",
        "title": "Account Payable Analyst",
        "email": None,
        "manager": None,
        "enabled": True,
        "groups": [ACCOUNTING_GROUP],
    }


def test_prepare_manager_only_mover(monkeypatch):
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

    plan = ps.prepare_mover(
        employee(),
        accounting_ad_user(),
    )

    assert list(plan["attribute_changes"]) == [
        "manager",
    ]

    assert plan["standard_attribute_changes"] == {}

    assert (
        plan["planned_operations"]["update_attributes"]
        is False
    )

    assert (
        plan["planned_operations"]["update_manager"]
        is True
    )


def test_prepare_department_mover(monkeypatch):
    monkeypatch.setattr(
        ps,
        "get_employee_identity_mapping",
        lambda employee: {
            "department": "Finance",
            "ou": FINANCE_OU,
            "groups": ["Finance Group"],
            "group_dns": [FINANCE_GROUP],
        },
    )

    monkeypatch.setattr(
        ps,
        "get_all_managed_birthright_group_dns",
        lambda: {
            ps.normalize_dn(ACCOUNTING_GROUP),
            ps.normalize_dn(FINANCE_GROUP),
        },
    )

    plan = ps.prepare_mover(
        employee(
            department="Finance",
            manager=None,
            manager_employee_id=None,
        ),
        accounting_ad_user(),
    )

    assert (
        plan["standard_attribute_changes"]
        ["department"]["new"]
        == "Finance"
    )

    assert (
        plan["planned_operations"]["update_attributes"]
        is True
    )

    assert (
        plan["planned_operations"]["move_user"]
        is True
    )

    assert plan["group_changes"] == {
        "add": [FINANCE_GROUP],
        "remove": [ACCOUNTING_GROUP],
    }


def test_execute_manager_only_mover(monkeypatch):
    state = accounting_ad_user()
    attribute_update_called = False

    plan = {
        "standard_attribute_changes": {},
        "attribute_changes": {
            "manager": {
                "old": None,
                "new": MANAGER_DN,
                "manager_employee_id": "0008",
            }
        },
        "planned_operations": {
            "update_attributes": False,
            "update_manager": True,
            "move_user": False,
            "remove_groups": False,
            "add_groups": False,
        },
        "identity_mapping": {
            "target_ou": ACCOUNTING_OU,
            "birthright_group_dns": [
                ACCOUNTING_GROUP,
            ],
        },
        "group_changes": {
            "add": [],
            "remove": [],
        },
    }

    def update_ad_user(**kwargs):
        nonlocal attribute_update_called
        attribute_update_called = True

        raise AssertionError(
            "Manager-only MOVER rewrote "
            "standard AD attributes."
        )

    def set_ad_manager(
        employee_id,
        manager_employee_id,
    ):
        state["manager"] = MANAGER_DN

        return {
            "success": True,
            "changed": True,
            "manager_dn": MANAGER_DN,
        }

    monkeypatch.setattr(
        ps,
        "update_ad_user",
        update_ad_user,
    )

    monkeypatch.setattr(
        ps,
        "set_ad_manager",
        set_ad_manager,
    )

    monkeypatch.setattr(
        ps,
        "get_user_by_employee_id",
        lambda employee_id: dict(state),
    )

    result = ps.execute_mover(
        employee(),
        plan,
    )

    assert attribute_update_called is False
    assert result["attribute_update"] is None

    assert (
        result["verified_ad_state"]["department"]
        == "Accounting"
    )

    assert (
        result["verified_ad_state"]["title"]
        == "Account Payable Analyst"
    )

    assert (
        result["verified_ad_state"]["manager"]
        == MANAGER_DN
    )

    assert result["verified_ad_state"]["groups"] == [
        ACCOUNTING_GROUP,
    ]
