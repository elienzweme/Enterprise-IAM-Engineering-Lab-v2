import pytest

from app.models.models import Employee
from app.services import provisioning_service as ps


AD_OPERATIONS = [
    "create_ad_user",
    "get_user_by_employee_id",
    "add_user_to_group",
    "remove_user_from_group",
    "set_ad_password",
    "require_password_change_at_next_logon",
    "enable_ad_user",
    "disable_ad_user",
    "update_ad_user",
    "move_ad_user",
    "set_ad_manager",
]


def blocked_ad_operation(*args, **kwargs):
    raise AssertionError(
        "A test attempted an unmocked Active Directory operation."
    )


@pytest.fixture(autouse=True)
def prevent_live_active_directory(monkeypatch):
    """
    Block every Active Directory operation automatically.

    Individual tests must explicitly mock any AD operation
    they expect the provisioning engine to perform.
    """

    for operation_name in AD_OPERATIONS:
        if hasattr(ps, operation_name):
            monkeypatch.setattr(
                ps,
                operation_name,
                blocked_ad_operation,
            )


@pytest.fixture
def joiner_employee():
    """
    Unsaved SQLAlchemy object used only in memory.

    This fixture does not connect to PostgreSQL.
    """

    return Employee(
        employee_id="T9001",
        first_name="Taylor",
        last_name="Tester",
        email="taylor.tester@corp.local",
        department="Accounting",
        job_title="Account Payable Analyst",
        manager=None,
        manager_employee_id=None,
        employment_status="Full-Time Permanent",
        source_system="PYTEST",
    )


@pytest.fixture
def accounting_mapping():
    return {
        "department": "Accounting",
        "ou": (
            "OU=Accounting,"
            "OU=Departments,"
            "DC=Corp,"
            "DC=local"
        ),
        "groups": [
            "Accounting Group",
        ],
        "group_dns": [
            (
                "CN=Accounting Group,"
                "OU=Domain Groups,"
                "DC=Corp,"
                "DC=local"
            ),
        ],
    }
