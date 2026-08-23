from app.models.models import Employee
from app.services import provisioning_service as ps


def test_manager_only_mover_does_not_update_attributes(
    mocker,
):
    """
    A manager-only MOVER must:

    - update the manager
    - not rewrite department
    - not rewrite title
    - not rewrite email
    - not move the account
    - not change groups
    - verify the final manager
    """

    employee = Employee(
        employee_id="T9100",
        first_name="Casey",
        last_name="Mover",
        email=None,
        department="Accounting",
        job_title="Account Payable Analyst",
        manager="Henry Woodward",
        manager_employee_id="0008",
        employment_status="Full-Time Permanent",
        source_system="PYTEST",
    )

    accounting_ou = (
        "OU=Accounting,"
        "OU=Departments,"
        "DC=Corp,"
        "DC=local"
    )

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

    accounting_mapping = {
        "department": "Accounting",
        "ou": accounting_ou,
        "groups": [
            "Accounting Group",
        ],
        "group_dns": [
            accounting_group,
        ],
    }

    current_ad_user = {
        "distinguished_name": (
            "CN=Casey Mover,"
            f"{accounting_ou}"
        ),
        "display_name": "Casey Mover",
        "first_name": "Casey",
        "last_name": "Mover",
        "sam_account_name": "casey.mover",
        "user_principal_name": (
            "casey.mover@corp.local"
        ),
        "employee_id": "T9100",
        "department": "Accounting",
        "title": "Account Payable Analyst",
        "email": None,
        "manager": None,
        "enabled": True,
        "groups": [
            accounting_group,
        ],
    }

    manager_ad_user = {
        "distinguished_name": manager_dn,
        "display_name": "Henry Woodward",
        "employee_id": "0008",
        "department": "Accounting",
        "title": "Manager of Accounting",
        "enabled": True,
        "groups": [
            accounting_group,
        ],
    }

    verified_ad_user = {
        **current_ad_user,
        "manager": manager_dn,
    }

    def fake_get_user(employee_id):
        employee_id = str(employee_id)

        if employee_id == "0008":
            return manager_ad_user

        if employee_id == "T9100":
            return verified_ad_user

        return None

    mocker.patch.object(
        ps,
        "get_employee_identity_mapping",
        return_value=accounting_mapping,
    )

    get_user_mock = mocker.patch.object(
        ps,
        "get_user_by_employee_id",
        side_effect=fake_get_user,
    )

    manager_mock = mocker.patch.object(
        ps,
        "set_ad_manager",
        return_value={
            "success": True,
            "changed": True,
            "employee_id": "T9100",
            "manager_employee_id": "0008",
            "manager_dn": manager_dn,
        },
    )

    plan = ps.prepare_mover(
        employee=employee,
        ad_user=current_ad_user,
    )

    assert list(
        plan["attribute_changes"].keys()
    ) == [
        "manager",
    ]

    assert (
        plan["standard_attribute_changes"]
        == {}
    )

    assert (
        plan["planned_operations"]["update_attributes"]
        is False
    )

    assert (
        plan["planned_operations"]["update_manager"]
        is True
    )

    assert (
        plan["planned_operations"]["move_user"]
        is False
    )

    assert (
        plan["planned_operations"]["remove_groups"]
        is False
    )

    assert (
        plan["planned_operations"]["add_groups"]
        is False
    )

    assert plan["ready_for_ad_write"] is True

    assert (
        plan["attribute_changes"]["manager"]["old"]
        is None
    )

    assert (
        plan["attribute_changes"]["manager"]["new"]
        == manager_dn
    )

    result = ps.execute_mover(
        employee=employee,
        plan=plan,
    )

    # Most important manager-only regression assertion:
    assert result["attribute_update"] is None

    assert result["ou_move"] is None
    assert result["groups_removed"] == []
    assert result["groups_added"] == []

    assert result["manager_update"]["success"] is True
    assert result["manager_update"]["changed"] is True

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
        == manager_dn
    )

    manager_mock.assert_called_once_with(
        employee_id="T9100",
        manager_employee_id="0008",
    )

    # One manager lookup during preparation and one final
    # employee lookup during execution.
    assert get_user_mock.call_count == 2


def test_department_mover_updates_access_and_ou(
    mocker,
):
    """
    A department MOVER must:

    1. Update only the changed standard attribute
    2. Move the user to the target OU
    3. Remove the old birthright group
    4. Add the new birthright group
    5. Verify the complete final AD state
    """

    employee = Employee(
        employee_id="T9101",
        first_name="Riley",
        last_name="DepartmentMover",
        email=None,
        department="Finance",
        job_title="Account Payable Analyst",
        manager=None,
        manager_employee_id=None,
        employment_status="Full-Time Permanent",
        source_system="PYTEST",
    )

    accounting_ou = (
        "OU=Accounting,"
        "OU=Departments,"
        "DC=Corp,"
        "DC=local"
    )

    finance_ou = (
        "OU=Finance,"
        "OU=Departments,"
        "DC=Corp,"
        "DC=local"
    )

    accounting_group = (
        "CN=Accounting Group,"
        "OU=Domain Groups,"
        "DC=Corp,"
        "DC=local"
    )

    finance_group = (
        "CN=Finance Group,"
        "OU=Domain Groups,"
        "DC=Corp,"
        "DC=local"
    )

    finance_mapping = {
        "department": "Finance",
        "ou": finance_ou,
        "groups": [
            "Finance Group",
        ],
        "group_dns": [
            finance_group,
        ],
    }

    current_ad_user = {
        "distinguished_name": (
            "CN=Riley DepartmentMover,"
            f"{accounting_ou}"
        ),
        "display_name": "Riley DepartmentMover",
        "first_name": "Riley",
        "last_name": "DepartmentMover",
        "sam_account_name": "riley.departmentmover",
        "user_principal_name": (
            "riley.departmentmover@corp.local"
        ),
        "employee_id": "T9101",
        "department": "Accounting",
        "title": "Account Payable Analyst",
        "email": None,
        "manager": None,
        "enabled": True,
        "groups": [
            accounting_group,
        ],
    }

    verified_ad_user = {
        **current_ad_user,
        "distinguished_name": (
            "CN=Riley DepartmentMover,"
            f"{finance_ou}"
        ),
        "department": "Finance",
        "groups": [
            finance_group,
        ],
    }

    operations = []

    def fake_update_ad_user(**kwargs):
        operations.append("update attributes")

        return {
            "success": True,
            "employee_id": "T9101",
            "attributes_updated": [
                "department",
            ],
        }

    def fake_move_ad_user(**kwargs):
        operations.append("move user")

        return {
            "success": True,
            "employee_id": "T9101",
            "target_ou": finance_ou,
        }

    def fake_remove_group(**kwargs):
        operations.append("remove old group")

        return {
            "success": True,
            "employee_id": "T9101",
            "group_dn": accounting_group,
        }

    def fake_add_group(**kwargs):
        operations.append("add new group")

        return {
            "success": True,
            "employee_id": "T9101",
            "group_dn": finance_group,
        }

    def fake_get_user(employee_id):
        assert str(employee_id) == "T9101"

        operations.append("verify final state")
        return verified_ad_user

    mocker.patch.object(
        ps,
        "get_employee_identity_mapping",
        return_value=finance_mapping,
    )

    update_mock = mocker.patch.object(
        ps,
        "update_ad_user",
        side_effect=fake_update_ad_user,
    )

    move_mock = mocker.patch.object(
        ps,
        "move_ad_user",
        side_effect=fake_move_ad_user,
    )

    remove_mock = mocker.patch.object(
        ps,
        "remove_user_from_group",
        side_effect=fake_remove_group,
    )

    add_mock = mocker.patch.object(
        ps,
        "add_user_to_group",
        side_effect=fake_add_group,
    )

    get_user_mock = mocker.patch.object(
        ps,
        "get_user_by_employee_id",
        side_effect=fake_get_user,
    )

    plan = ps.prepare_mover(
        employee=employee,
        ad_user=current_ad_user,
    )

    assert list(
        plan["attribute_changes"].keys()
    ) == [
        "department",
    ]

    assert list(
        plan["standard_attribute_changes"].keys()
    ) == [
        "department",
    ]

    assert (
        plan["standard_attribute_changes"]
        ["department"]["old"]
        == "Accounting"
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
        plan["planned_operations"]["update_manager"]
        is False
    )

    assert (
        plan["planned_operations"]["move_user"]
        is True
    )

    assert (
        plan["planned_operations"]["remove_groups"]
        is True
    )

    assert (
        plan["planned_operations"]["add_groups"]
        is True
    )

    assert plan["ready_for_ad_write"] is True

    assert (
        plan["group_changes"]["remove"]
        == [accounting_group]
    )

    assert (
        plan["group_changes"]["add"]
        == [finance_group]
    )

    result = ps.execute_mover(
        employee=employee,
        plan=plan,
    )

    assert result["attribute_update"]["success"] is True
    assert result["ou_move"]["success"] is True

    assert len(result["groups_removed"]) == 1
    assert len(result["groups_added"]) == 1

    verified = result["verified_ad_state"]

    assert verified["department"] == "Finance"

    assert (
        verified["title"]
        == "Account Payable Analyst"
    )

    assert verified["manager"] is None

    assert verified["groups"] == [
        finance_group,
    ]

    assert finance_ou.lower() in (
        verified["distinguished_name"].lower()
    )

    # Validate the required provisioning sequence.
    assert operations == [
        "update attributes",
        "move user",
        "remove old group",
        "add new group",
        "verify final state",
    ]

    update_mock.assert_called_once()
    move_mock.assert_called_once_with(
        employee_id="T9101",
        target_ou=finance_ou,
    )

    remove_mock.assert_called_once_with(
        employee_id="T9101",
        group_dn=accounting_group,
    )

    add_mock.assert_called_once_with(
        employee_id="T9101",
        group_dn=finance_group,
    )

    get_user_mock.assert_called_once_with(
        "T9101"
    )
