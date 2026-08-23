from app.models.models import Employee
from app.services import provisioning_service as ps


def test_normal_leaver_executes_complete_deprovisioning(
    mocker,
):
    """
    A normal LEAVER must execute in this order:

    1. Disable account
    2. Remove direct groups
    3. Clear manager
    4. Move to Disabled Users
    5. Verify final AD state
    """

    employee = Employee(
        employee_id="T9200",
        first_name="Avery",
        last_name="Leaver",
        email="avery.leaver@corp.local",
        department="Accounting",
        job_title="Account Payable Analyst",
        manager="Henry Woodward",
        manager_employee_id="0008",
        employment_status="Terminated",
        source_system="PYTEST",
    )

    accounting_ou = (
        "OU=Accounting,"
        "OU=Departments,"
        "DC=Corp,"
        "DC=local"
    )

    disabled_ou = ps.AD_DISABLED_USERS_OU

    accounting_group = (
        "CN=Accounting Group,"
        "OU=Domain Groups,"
        "DC=Corp,"
        "DC=local"
    )

    manager_dn = (
        "CN=Henry Woodward,"
        "OU=Accounting,"
        "OU=Departments,"
        "DC=Corp,"
        "DC=local"
    )

    current_ad_user = {
        "distinguished_name": (
            "CN=Avery Leaver,"
            f"{accounting_ou}"
        ),
        "display_name": "Avery Leaver",
        "first_name": "Avery",
        "last_name": "Leaver",
        "sam_account_name": "avery.leaver",
        "user_principal_name": (
            "avery.leaver@corp.local"
        ),
        "employee_id": "T9200",
        "department": "Accounting",
        "title": "Account Payable Analyst",
        "email": "avery.leaver@corp.local",
        "manager": manager_dn,
        "enabled": True,
        "groups": [
            accounting_group,
        ],
    }

    verified_ad_user = {
        **current_ad_user,
        "distinguished_name": (
            "CN=Avery Leaver,"
            f"{disabled_ou}"
        ),
        "manager": None,
        "enabled": False,
        "groups": [],
    }

    operations = []

    def fake_disable(*args, **kwargs):
        operations.append("disable account")

        return {
            "success": True,
            "changed": True,
            "employee_id": "T9200",
            "enabled": False,
        }

    def fake_remove_group(*args, **kwargs):
        operations.append("remove group")

        return {
            "success": True,
            "changed": True,
            "employee_id": "T9200",
            "group_dn": accounting_group,
        }

    def fake_clear_manager(*args, **kwargs):
        operations.append("clear manager")

        return {
            "success": True,
            "changed": True,
            "employee_id": "T9200",
            "manager_employee_id": None,
            "manager_dn": None,
        }

    def fake_move(*args, **kwargs):
        operations.append("move user")

        return {
            "success": True,
            "changed": True,
            "employee_id": "T9200",
            "target_ou": disabled_ou,
        }

    def fake_get_user(employee_id):
        assert str(employee_id) == "T9200"

        operations.append("verify final state")
        return verified_ad_user

    disable_mock = mocker.patch.object(
        ps,
        "disable_ad_user",
        side_effect=fake_disable,
    )

    remove_mock = mocker.patch.object(
        ps,
        "remove_user_from_group",
        side_effect=fake_remove_group,
    )

    manager_mock = mocker.patch.object(
        ps,
        "set_ad_manager",
        side_effect=fake_clear_manager,
    )

    move_mock = mocker.patch.object(
        ps,
        "move_ad_user",
        side_effect=fake_move,
    )

    get_user_mock = mocker.patch.object(
        ps,
        "get_user_by_employee_id",
        side_effect=fake_get_user,
    )

    plan = ps.prepare_leaver(
        employee=employee,
        ad_user=current_ad_user,
    )

    assert plan["operation"] == "DISABLE_AD_USER"
    assert plan["employee_id"] == "T9200"
    assert plan["ready_for_ad_write"] is True
    assert plan["execution_enabled"] is True

    assert plan["groups_to_remove"] == [
        accounting_group,
    ]

    assert plan["clear_manager"] is True
    assert plan["target_ou"] == disabled_ou

    assert plan["planned_operations"] == {
        "disable_account": True,
        "remove_groups": True,
        "clear_manager": True,
        "move_user": True,
    }

    result = ps.execute_leaver(
        employee=employee,
        plan=plan,
    )

    verified = result["verified_ad_state"]

    assert verified["enabled"] is False
    assert verified["manager"] is None
    assert verified["groups"] == []

    assert disabled_ou.lower() in (
        verified["distinguished_name"].lower()
    )

    # Validate the required security-sensitive sequence.
    assert operations == [
        "disable account",
        "remove group",
        "clear manager",
        "move user",
        "verify final state",
    ]

    disable_mock.assert_called_once()

    remove_mock.assert_called_once_with(
        employee_id="T9200",
        group_dn=accounting_group,
    )

    manager_mock.assert_called_once_with(
        employee_id="T9200",
        manager_employee_id=None,
    )

    move_mock.assert_called_once_with(
        employee_id="T9200",
        target_ou=disabled_ou,
    )

    get_user_mock.assert_called_once_with(
        "T9200"
    )

def test_already_satisfied_leaver_requires_no_ad_write():
    """A fully deprovisioned account must produce a no-change plan."""
    from app.models.models import Employee
    from app.services import provisioning_service as ps

    employee = Employee(
        employee_id="T9201",
        first_name="Taylor",
        last_name="AlreadyDisabled",
        email="taylor.alreadydisabled@corp.local",
        department="Accounting",
        job_title="Account Payable Analyst",
        manager=None,
        manager_employee_id=None,
        employment_status="Terminated",
        source_system="PYTEST",
    )

    disabled_ou = ps.AD_DISABLED_USERS_OU

    ad_user = {
        "distinguished_name": (
            f"CN=Taylor AlreadyDisabled,{disabled_ou}"
        ),
        "display_name": "Taylor AlreadyDisabled",
        "employee_id": "T9201",
        "department": "Accounting",
        "title": "Account Payable Analyst",
        "manager": None,
        "enabled": False,
        "groups": [],
    }

    plan = ps.prepare_leaver(
        employee=employee,
        ad_user=ad_user,
    )

    assert plan["ready_for_ad_write"] is False
    assert plan["groups_to_remove"] == []
    assert plan["clear_manager"] is False
    assert plan["target_ou"] == disabled_ou

    assert plan["planned_operations"] == {
        "disable_account": False,
        "remove_groups": False,
        "clear_manager": False,
        "move_user": False,
    }

def test_partial_leaver_retry_executes_only_remaining_steps(mocker):
    """
    If a previous LEAVER attempt disabled the account and removed groups,
    retry only the unfinished manager-clear and OU-move operations.
    """
    from app.models.models import Employee
    from app.services import provisioning_service as ps

    employee = Employee(
        employee_id="T9202",
        first_name="Casey",
        last_name="PartialLeaver",
        email="casey.partialleaver@corp.local",
        department="Accounting",
        job_title="Account Payable Analyst",
        manager="Henry Woodward",
        manager_employee_id="0008",
        employment_status="Terminated",
        source_system="PYTEST",
    )

    disabled_ou = ps.AD_DISABLED_USERS_OU

    current_ad_user = {
        "distinguished_name": (
            "CN=Casey PartialLeaver,"
            "OU=Accounting,OU=Departments,"
            "DC=Corp,DC=local"
        ),
        "display_name": "Casey PartialLeaver",
        "employee_id": "T9202",
        "department": "Accounting",
        "title": "Account Payable Analyst",
        "manager": (
            "CN=Henry Woodward,"
            "OU=Accounting,OU=Departments,"
            "DC=Corp,DC=local"
        ),
        "enabled": False,
        "groups": [],
    }

    verified_user = {
        **current_ad_user,
        "distinguished_name": (
            f"CN=Casey PartialLeaver,{disabled_ou}"
        ),
        "manager": None,
        "enabled": False,
        "groups": [],
    }

    operations = []

    disable_mock = mocker.patch.object(
        ps,
        "disable_ad_user",
    )

    remove_mock = mocker.patch.object(
        ps,
        "remove_user_from_group",
    )

    def fake_clear_manager(employee_id, manager_employee_id):
        operations.append("clear manager")
        return {
            "success": True,
            "changed": True,
            "employee_id": employee_id,
            "manager_employee_id": manager_employee_id,
            "manager_dn": None,
        }

    def fake_move(employee_id, target_ou):
        operations.append("move user")
        return {
            "success": True,
            "changed": True,
            "employee_id": employee_id,
            "target_ou": target_ou,
        }

    def fake_get_user(employee_id):
        operations.append("verify")
        return verified_user

    manager_mock = mocker.patch.object(
        ps,
        "set_ad_manager",
        side_effect=fake_clear_manager,
    )

    move_mock = mocker.patch.object(
        ps,
        "move_ad_user",
        side_effect=fake_move,
    )

    mocker.patch.object(
        ps,
        "get_user_by_employee_id",
        side_effect=fake_get_user,
    )

    plan = ps.prepare_leaver(
        employee=employee,
        ad_user=current_ad_user,
    )

    assert plan["ready_for_ad_write"] is True
    assert plan["groups_to_remove"] == []
    assert plan["clear_manager"] is True
    assert plan["target_ou"] == disabled_ou

    assert plan["planned_operations"] == {
        "disable_account": False,
        "remove_groups": False,
        "clear_manager": True,
        "move_user": True,
    }

    result = ps.execute_leaver(
        employee=employee,
        plan=plan,
    )

    assert operations == [
        "clear manager",
        "move user",
        "verify",
    ]

    disable_mock.assert_not_called()
    remove_mock.assert_not_called()

    manager_mock.assert_called_once_with(
        employee_id="T9202",
        manager_employee_id=None,
    )

    move_mock.assert_called_once_with(
        employee_id="T9202",
        target_ou=disabled_ou,
    )

    verified = result["verified_ad_state"]

    assert verified["enabled"] is False
    assert verified["manager"] is None
    assert verified["groups"] == []
    assert disabled_ou in verified["distinguished_name"]

def test_leaver_stops_after_failed_disable_operation(mocker):
    """
    LEAVER must stop immediately if the initial account-disable operation
    fails. Later deprovisioning operations must not run.
    """
    import pytest

    from app.models.models import Employee
    from app.services import provisioning_service as ps

    employee = Employee(
        employee_id="T9203",
        first_name="Alex",
        last_name="LdapFailure",
        email="alex.ldapfailure@corp.local",
        department="Accounting",
        job_title="Account Payable Analyst",
        manager="Henry Woodward",
        manager_employee_id="0008",
        employment_status="Terminated",
        source_system="PYTEST",
    )

    accounting_group = (
        "CN=Accounting Group,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local"
    )

    current_ad_user = {
        "distinguished_name": (
            "CN=Alex LdapFailure,"
            "OU=Accounting,OU=Departments,"
            "DC=Corp,DC=local"
        ),
        "display_name": "Alex LdapFailure",
        "employee_id": "T9203",
        "department": "Accounting",
        "title": "Account Payable Analyst",
        "manager": (
            "CN=Henry Woodward,"
            "OU=Accounting,OU=Departments,"
            "DC=Corp,DC=local"
        ),
        "enabled": True,
        "groups": [accounting_group],
    }

    disable_mock = mocker.patch.object(
        ps,
        "disable_ad_user",
        side_effect=RuntimeError(
            "Simulated LDAP disable failure"
        ),
    )

    remove_mock = mocker.patch.object(
        ps,
        "remove_user_from_group",
    )

    manager_mock = mocker.patch.object(
        ps,
        "set_ad_manager",
    )

    move_mock = mocker.patch.object(
        ps,
        "move_ad_user",
    )

    get_user_mock = mocker.patch.object(
        ps,
        "get_user_by_employee_id",
    )

    plan = ps.prepare_leaver(
        employee=employee,
        ad_user=current_ad_user,
    )

    assert plan["planned_operations"]["disable_account"] is True

    with pytest.raises(
        RuntimeError,
        match="Simulated LDAP disable failure",
    ):
        ps.execute_leaver(
            employee=employee,
            plan=plan,
        )

    disable_mock.assert_called_once_with(
        employee_id="T9203",
    )

    remove_mock.assert_not_called()
    manager_mock.assert_not_called()
    move_mock.assert_not_called()
    get_user_mock.assert_not_called()

