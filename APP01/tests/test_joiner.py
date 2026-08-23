from app.services import provisioning_service as ps


def test_prepare_normal_joiner(
    mocker,
    joiner_employee,
    accounting_mapping,
):
    """
    A new employee without an existing AD account should
    produce an executable JOINER plan.

    No AD write is performed by preparation.
    """

    mocker.patch.object(
        ps,
        "get_employee_identity_mapping",
        return_value=accounting_mapping,
    )

    plan = ps.prepare_joiner(
        employee=joiner_employee,
        ad_user=None,
    )

    assert plan["operation"] == "CREATE_AD_USER"
    assert plan["employee_id"] == "T9001"
    assert plan["ready_for_ad_write"] is True
    assert plan["execution_enabled"] is True

    assert (
        plan["identity_mapping"]["target_ou"]
        == accounting_mapping["ou"]
    )

    assert (
        plan["identity_mapping"]["birthright_group_dns"]
        == accounting_mapping["group_dns"]
    )

    assert (
        plan["recovery"]["partial_joiner"]
        is False
    )


def test_execute_normal_joiner_without_manager(
    mocker,
    joiner_employee,
    accounting_mapping,
):
    """
    Execute a normal JOINER entirely through mocks.

    This validates:
    - account creation
    - birthright group assignment
    - temporary password configuration
    - forced password change
    - account enablement
    - final state verification
    """

    target_ou = accounting_mapping["ou"]
    accounting_group = accounting_mapping["group_dns"][0]

    mocker.patch.object(
        ps,
        "get_employee_identity_mapping",
        return_value=accounting_mapping,
    )

    plan = ps.prepare_joiner(
        employee=joiner_employee,
        ad_user=None,
    )

    created_user = {
        "distinguished_name": (
            "CN=Taylor Tester,"
            f"{target_ou}"
        ),
        "display_name": "Taylor Tester",
        "first_name": "Taylor",
        "last_name": "Tester",
        "sam_account_name": "taylor.tester",
        "user_principal_name": (
            "taylor.tester@corp.local"
        ),
        "employee_id": "T9001",
        "department": "Accounting",
        "title": "Account Payable Analyst",
        "email": "taylor.tester@corp.local",
        "manager": None,
        "enabled": False,
        "groups": [],
    }

    verified_user = {
        **created_user,
        "enabled": True,
        "groups": [
            accounting_group,
        ],
    }

    get_user_mock = mocker.patch.object(
        ps,
        "get_user_by_employee_id",
        side_effect=[
            None,
            created_user,
            verified_user,
        ],
    )

    create_mock = mocker.patch.object(
        ps,
        "create_ad_user",
        return_value={
            "success": True,
            "employee_id": "T9001",
            "created": True,
        },
    )

    add_group_mock = mocker.patch.object(
        ps,
        "add_user_to_group",
        return_value={
            "success": True,
            "employee_id": "T9001",
            "group_dn": accounting_group,
        },
    )

    password_mock = mocker.patch.object(
        ps,
        "set_ad_password",
        return_value={
            "success": True,
        },
    )

    password_change_mock = mocker.patch.object(
        ps,
        "require_password_change_at_next_logon",
        return_value={
            "success": True,
        },
    )

    enable_mock = mocker.patch.object(
        ps,
        "enable_ad_user",
        return_value={
            "success": True,
            "employee_id": "T9001",
            "enabled": True,
        },
    )

    result = ps.execute_joiner(
        employee=joiner_employee,
        plan=plan,
    )

    assert result["success"] is True
    assert result["employee_id"] == "T9001"

    assert (
        result["recovered_partial_joiner"]
        is False
    )

    assert (
        result["verified_ad_state"]["enabled"]
        is True
    )

    assert (
        result["verified_ad_state"]["manager"]
        is None
    )

    assert accounting_group in (
        result["verified_ad_state"]["groups"]
    )

    # The plaintext temporary password must never be returned.
    assert "temporary_password" not in result

    create_mock.assert_called_once()
    add_group_mock.assert_called_once()
    password_mock.assert_called_once()
    password_change_mock.assert_called_once()
    enable_mock.assert_called_once()

    assert get_user_mock.call_count == 3


def test_joiner_assigns_and_verifies_manager(
    mocker,
    accounting_mapping,
):
    """
    A JOINER whose HR record contains manager_employee_id
    must resolve, assign and verify that manager.

    All Active Directory operations remain mocked.
    """

    from app.models.models import Employee

    employee = Employee(
        employee_id="T9002",
        first_name="Jordan",
        last_name="ManagerTest",
        email="jordan.managertest@corp.local",
        department="Accounting",
        job_title="Account Payable Analyst",
        manager="Henry Woodward",
        manager_employee_id="0008",
        employment_status="Full-Time Permanent",
        source_system="PYTEST",
    )

    target_ou = accounting_mapping["ou"]
    accounting_group = accounting_mapping["group_dns"][0]

    manager_dn = (
        "CN=Henry Woodward,"
        "OU=Accounting,"
        "OU=Departments,"
        "DC=Corp,"
        "DC=local"
    )

    manager_user = {
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

    created_user = {
        "distinguished_name": (
            "CN=Jordan ManagerTest,"
            f"{target_ou}"
        ),
        "display_name": "Jordan ManagerTest",
        "first_name": "Jordan",
        "last_name": "ManagerTest",
        "sam_account_name": "jordan.managertest",
        "user_principal_name": (
            "jordan.managertest@corp.local"
        ),
        "employee_id": "T9002",
        "department": "Accounting",
        "title": "Account Payable Analyst",
        "email": "jordan.managertest@corp.local",
        "manager": None,
        "enabled": False,
        "groups": [],
    }

    verified_user = {
        **created_user,
        "manager": manager_dn,
        "enabled": True,
        "groups": [
            accounting_group,
        ],
    }

    employee_states = iter([
        None,
        created_user,
        verified_user,
    ])

    def fake_get_user(employee_id):
        employee_id = str(employee_id)

        if employee_id == "0008":
            return manager_user

        if employee_id == "T9002":
            return next(employee_states)

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

    create_mock = mocker.patch.object(
        ps,
        "create_ad_user",
        return_value={
            "success": True,
            "employee_id": "T9002",
            "created": True,
        },
    )

    add_group_mock = mocker.patch.object(
        ps,
        "add_user_to_group",
        return_value={
            "success": True,
            "employee_id": "T9002",
            "group_dn": accounting_group,
        },
    )

    manager_mock = mocker.patch.object(
        ps,
        "set_ad_manager",
        return_value={
            "success": True,
            "changed": True,
            "employee_id": "T9002",
            "manager_employee_id": "0008",
            "manager_dn": manager_dn,
        },
    )

    mocker.patch.object(
        ps,
        "set_ad_password",
        return_value={
            "success": True,
        },
    )

    mocker.patch.object(
        ps,
        "require_password_change_at_next_logon",
        return_value={
            "success": True,
        },
    )

    mocker.patch.object(
        ps,
        "enable_ad_user",
        return_value={
            "success": True,
            "employee_id": "T9002",
            "enabled": True,
        },
    )

    plan = ps.prepare_joiner(
        employee=employee,
        ad_user=None,
    )

    assert "manager_change" in plan

    assert (
        plan["manager_change"]["manager_employee_id"]
        == "0008"
    )

    assert (
        plan["manager_change"]["new"]
        == manager_dn
    )

    assert (
        plan["manager_change"]["assignment_required"]
        is True
    )

    result = ps.execute_joiner(
        employee=employee,
        plan=plan,
    )

    assert result["success"] is True
    assert result["employee_id"] == "T9002"

    assert (
        result["verified_ad_state"]["manager"]
        == manager_dn
    )

    assert result["manager_update"]["success"] is True
    assert result["manager_update"]["changed"] is True

    manager_mock.assert_called_once_with(
        employee_id="T9002",
        manager_employee_id="0008",
    )

    create_mock.assert_called_once()
    add_group_mock.assert_called_once()

    # Manager lookup plus three employee-state reads occurred.
    assert get_user_mock.call_count >= 4

    # A temporary password must never appear in the result.
    assert "temporary_password" not in result


def test_partial_joiner_recovery(
    mocker,
    joiner_employee,
    accounting_mapping,
):
    """
    A matching disabled account in the correct OU should be
    recovered without calling create_ad_user again.
    """

    target_ou = accounting_mapping["ou"]
    accounting_group = accounting_mapping["group_dns"][0]

    existing_disabled_user = {
        "distinguished_name": (
            "CN=Taylor Tester,"
            f"{target_ou}"
        ),
        "display_name": "Taylor Tester",
        "first_name": "Taylor",
        "last_name": "Tester",
        "sam_account_name": "taylor.tester",
        "user_principal_name": (
            "taylor.tester@corp.local"
        ),
        "employee_id": "T9001",
        "department": "Accounting",
        "title": "Account Payable Analyst",
        "email": "taylor.tester@corp.local",
        "manager": None,
        "enabled": False,
        "groups": [
            accounting_group,
        ],
    }

    verified_user = {
        **existing_disabled_user,
        "enabled": True,
    }

    mocker.patch.object(
        ps,
        "get_employee_identity_mapping",
        return_value=accounting_mapping,
    )

    plan = ps.prepare_joiner(
        employee=joiner_employee,
        ad_user=existing_disabled_user,
    )

    assert (
        plan["recovery"]["partial_joiner"]
        is True
    )

    assert (
        plan["recovery"]["existing_ad_user"]
        == existing_disabled_user
    )

    get_user_mock = mocker.patch.object(
        ps,
        "get_user_by_employee_id",
        side_effect=[
            existing_disabled_user,
            existing_disabled_user,
            verified_user,
        ],
    )

    password_mock = mocker.patch.object(
        ps,
        "set_ad_password",
        return_value={
            "success": True,
        },
    )

    password_change_mock = mocker.patch.object(
        ps,
        "require_password_change_at_next_logon",
        return_value={
            "success": True,
        },
    )

    enable_mock = mocker.patch.object(
        ps,
        "enable_ad_user",
        return_value={
            "success": True,
            "employee_id": "T9001",
            "enabled": True,
        },
    )

    result = ps.execute_joiner(
        employee=joiner_employee,
        plan=plan,
    )

    assert result["success"] is True

    assert (
        result["recovered_partial_joiner"]
        is True
    )

    assert (
        result["account_creation"]["created"]
        is False
    )

    assert (
        result["account_creation"]["recovered"]
        is True
    )

    assert (
        result["verified_ad_state"]["enabled"]
        is True
    )

    assert (
        result["groups_added"]
        == []
    )

    assert accounting_group in (
        result["groups_already_present"]
    )

    password_mock.assert_called_once()
    password_change_mock.assert_called_once()
    enable_mock.assert_called_once()

    assert get_user_mock.call_count == 3


def test_joiner_missing_manager_fails_safely(
    mocker,
    accounting_mapping,
):
    """
    If HR specifies a manager_employee_id that cannot be
    resolved in AD, JOINER preparation must fail safely.
    """

    import pytest
    from app.models.models import Employee

    employee = Employee(
        employee_id="T9003",
        first_name="Morgan",
        last_name="MissingManager",
        email="morgan.missingmanager@corp.local",
        department="Accounting",
        job_title="Account Payable Analyst",
        manager="Unknown Manager",
        manager_employee_id="9999",
        employment_status="Full-Time Permanent",
        source_system="PYTEST",
    )

    mocker.patch.object(
        ps,
        "get_employee_identity_mapping",
        return_value=accounting_mapping,
    )

    manager_lookup = mocker.patch.object(
        ps,
        "get_user_by_employee_id",
        return_value=None,
    )

    with pytest.raises(
        ValueError,
        match="(?i)manager",
    ):
        ps.prepare_joiner(
            employee=employee,
            ad_user=None,
        )

    manager_lookup.assert_called_once_with(
        "9999"
    )
