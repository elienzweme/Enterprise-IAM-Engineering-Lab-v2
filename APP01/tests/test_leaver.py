
from types import SimpleNamespace

from app.services import provisioning_service as ps


ACCOUNTING_OU = (
    "OU=Accounting,OU=Departments,DC=Corp,DC=local"
)

DISABLED_OU = (
    "OU=Disabled Users,DC=Corp,DC=local"
)

ACCOUNTING_GROUP = (
    "CN=Accounting Group,OU=Domain Groups,DC=Corp,DC=local"
)

REMOTE_GROUP = (
    "CN=Remote Access Users,OU=Domain Groups,DC=Corp,DC=local"
)

MANAGER_DN = (
    "CN=Henry Woodward,OU=Accounting,"
    "OU=Departments,DC=Corp,DC=local"
)


def employee():
    return SimpleNamespace(
        employee_id="TEST-LEAVER",
        employment_status="Terminated",
    )


def active_ad_state():
    return {
        "distinguished_name": (
            "CN=Test Leaver," + ACCOUNTING_OU
        ),
        "enabled": True,
        "manager": MANAGER_DN,
        "groups": [
            ACCOUNTING_GROUP,
            REMOTE_GROUP,
        ],
    }


def test_prepare_leaver_calculates_operations(monkeypatch):
    monkeypatch.setattr(
        ps,
        "AD_DISABLED_USERS_OU",
        DISABLED_OU,
    )

    plan = ps.prepare_leaver(
        employee(),
        active_ad_state(),
    )

    assert plan["execution_enabled"] is True
    assert plan["ready_for_ad_write"] is True

    assert plan["groups_to_remove"] == [
        ACCOUNTING_GROUP,
        REMOTE_GROUP,
    ]

    assert plan["planned_operations"] == {
        "disable_account": True,
        "remove_groups": True,
        "clear_manager": True,
        "move_user": True,
    }


def test_execute_leaver_and_verify(monkeypatch):
    monkeypatch.setattr(
        ps,
        "AD_DISABLED_USERS_OU",
        DISABLED_OU,
    )

    state = active_ad_state()
    operations = []

    def disable_ad_user(employee_id):
        operations.append("disable")
        state["enabled"] = False
        return {
            "success": True,
            "enabled": False,
        }

    def remove_user_from_group(employee_id, group_dn):
        operations.append("remove_group")
        state["groups"].remove(group_dn)
        return {
            "success": True,
            "group_dn": group_dn,
        }

    def set_ad_manager(employee_id, manager_employee_id):
        operations.append("clear_manager")
        state["manager"] = None
        return {
            "success": True,
            "manager_dn": None,
        }

    def move_ad_user(employee_id, target_ou):
        operations.append("move")
        state["distinguished_name"] = (
            "CN=Test Leaver," + target_ou
        )
        return {
            "success": True,
            "new_dn": state["distinguished_name"],
        }

    monkeypatch.setattr(
        ps,
        "disable_ad_user",
        disable_ad_user,
    )
    monkeypatch.setattr(
        ps,
        "remove_user_from_group",
        remove_user_from_group,
    )
    monkeypatch.setattr(
        ps,
        "set_ad_manager",
        set_ad_manager,
    )
    monkeypatch.setattr(
        ps,
        "move_ad_user",
        move_ad_user,
    )
    monkeypatch.setattr(
        ps,
        "get_user_by_employee_id",
        lambda employee_id: dict(state),
    )

    plan = ps.prepare_leaver(
        employee(),
        dict(state),
    )

    result = ps.execute_leaver(
        employee(),
        plan,
    )

    verified = result["verified_ad_state"]

    assert result["success"] is True
    assert verified["enabled"] is False
    assert verified["manager"] is None
    assert verified["groups"] == []
    assert verified["distinguished_name"].endswith(
        DISABLED_OU
    )

    assert operations == [
        "disable",
        "remove_group",
        "remove_group",
        "clear_manager",
        "move",
    ]


def test_leaver_already_satisfied(monkeypatch):
    monkeypatch.setattr(
        ps,
        "AD_DISABLED_USERS_OU",
        DISABLED_OU,
    )

    final_state = {
        "distinguished_name": (
            "CN=Test Leaver," + DISABLED_OU
        ),
        "enabled": False,
        "manager": None,
        "groups": [],
    }

    plan = ps.prepare_leaver(
        employee(),
        final_state,
    )

    assert plan["ready_for_ad_write"] is False
    assert not any(
        plan["planned_operations"].values()
    )


def test_partial_leaver_retry(monkeypatch):
    monkeypatch.setattr(
        ps,
        "AD_DISABLED_USERS_OU",
        DISABLED_OU,
    )

    partial_state = {
        "distinguished_name": (
            "CN=Test Leaver," + ACCOUNTING_OU
        ),
        "enabled": False,
        "manager": MANAGER_DN,
        "groups": [REMOTE_GROUP],
    }

    plan = ps.prepare_leaver(
        employee(),
        partial_state,
    )

    assert (
        plan["planned_operations"]["disable_account"]
        is False
    )
    assert plan["groups_to_remove"] == [REMOTE_GROUP]
    assert (
        plan["planned_operations"]["clear_manager"]
        is True
    )
    assert (
        plan["planned_operations"]["move_user"]
        is True
    )
