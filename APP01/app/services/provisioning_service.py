# app/services/provisioning_service.py

import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.models import (
    Employee,
    IdentityRequest,
    AuditEvent,
)

from app.services.ad_service import (
    get_user_by_employee_id,
    test_ad_connection,
    create_ad_user,
    update_ad_user,
    enable_ad_user,
    disable_ad_user,
    move_ad_user,
    add_user_to_group,
    remove_user_from_group,
    set_ad_manager,
    generate_temporary_password,
    set_ad_password,
    require_password_change_at_next_logon,
    AD_DISABLED_USERS_OU,
)

from app.config.identity_mapping import (
    get_identity_mapping,
    GROUP_DN_MAPPING,
)


# ============================================================
# Constants
# ============================================================

SUPPORTED_ACTIONS = {
    "JOINER",
    "MOVER",
    "LEAVER",
}


# ============================================================
# DN Helpers
# ============================================================

def normalize_dn(
    value: str | None,
) -> str:
    """
    Normalize an Active Directory DN for comparison.
    """

    if not value:
        return ""

    return (
        value
        .strip()
        .lower()
        .replace(" ", "")
    )


def get_parent_dn(
    distinguished_name: str | None,
) -> str | None:
    """
    Extract the parent OU/DN from a user's DN.

    Example:

        CN=Michael Smith,OU=HR,OU=Departments,DC=Corp,DC=local

    becomes:

        OU=HR,OU=Departments,DC=Corp,DC=local
    """

    if not distinguished_name:
        return None

    parts = distinguished_name.split(
        ",",
        1,
    )

    if len(parts) != 2:
        return None

    return parts[1]


# ============================================================
# Database Helpers
# ============================================================

def get_identity_request(
    db: Session,
    request_id: str,
) -> IdentityRequest:
    """
    Retrieve an IdentityRequest.
    """

    request = (
        db.query(IdentityRequest)
        .filter(
            IdentityRequest.request_id
            == request_id
        )
        .first()
    )

    if not request:
        raise ValueError(
            f"Identity request {request_id} not found"
        )

    return request


def get_employee(
    db: Session,
    employee_id: str,
) -> Employee:
    """
    Retrieve an IAM employee record.
    """

    employee = (
        db.query(Employee)
        .filter(
            Employee.employee_id
            == employee_id
        )
        .first()
    )

    if not employee:
        raise ValueError(
            f"Employee {employee_id} not found"
        )

    return employee


# ============================================================
# Audit Helper
# ============================================================

def create_audit_event(
    db: Session,
    request: IdentityRequest,
    event_type: str,
    result: str,
    details: dict,
):
    """
    Write an IAM provisioning event.
    """

    event = AuditEvent(
        request_id=request.request_id,
        employee_id=request.employee_id,
        event_type=event_type,
        system="Active Directory",
        result=result,
        details=json.dumps(
            details,
            default=str,
        ),
        timestamp=datetime.utcnow(),
    )

    db.add(event)


# ============================================================
# Provisioning Validation
# ============================================================

def validate_request_for_provisioning(
    request: IdentityRequest,
):
    """
    Enforce approval boundary before AD provisioning.
    """

    action = (
        request.action
        or ""
    ).upper()

    if action not in SUPPORTED_ACTIONS:

        raise ValueError(
            f"Unsupported lifecycle action: {action}"
        )

    allowed_statuses = {
        "Approved",
        "Failed",
    }

    if request.status not in allowed_statuses:

        raise ValueError(
            (
                f"Request {request.request_id} "
                f"has status '{request.status}'. "
                "Only Approved requests or previously "
                "Failed requests can be provisioned."
            )
        )

    if not request.approved_by:

        raise ValueError(
            (
                f"Request {request.request_id} "
                "does not contain an approver."
            )
        )

    if request.completed_at is not None:

        raise ValueError(
            (
                f"Request {request.request_id} "
                "has already been completed."
            )
        )


# ============================================================
# Desired Employee State
# ============================================================

def employee_snapshot(
    employee: Employee,
) -> dict:
    """
    Build desired identity state from the IAM database.
    """

    return {
        "employee_id":
            employee.employee_id,

        "first_name":
            employee.first_name,

        "last_name":
            employee.last_name,

        "email":
            employee.email,

        "department":
            employee.department,

        "job_title":
            employee.job_title,

        "manager":
            employee.manager,

        "manager_employee_id":
            getattr(employee, "manager_employee_id", None),

        "employment_status":
            employee.employment_status,
    }


# ============================================================
# Identity Mapping
# ============================================================

def get_employee_identity_mapping(
    employee: Employee,
) -> dict:
    """
    Resolve department into OU and birthright groups.
    """

    if not employee.department:

        raise ValueError(
            (
                f"Employee {employee.employee_id} "
                "does not have a department."
            )
        )

    return get_identity_mapping(
        employee.department
    )


# ============================================================
# Managed Birthright Groups
# ============================================================

def get_all_managed_birthright_group_dns() -> set[str]:
    """
    Return all department groups controlled automatically
    by IAM.

    Privileged/conditional groups are intentionally excluded.
    """

    return {
        normalize_dn(group_dn)
        for group_dn
        in GROUP_DN_MAPPING.values()
        if group_dn
    }


# ============================================================
# Group Delta Calculation
# ============================================================

def calculate_group_changes(
    current_groups: list[str] | None,
    desired_group_dns: list[str] | None,
) -> dict:
    """
    Determine birthright group additions/removals.
    """

    current_groups = (
        current_groups
        or []
    )

    desired_group_dns = (
        desired_group_dns
        or []
    )

    current_normalized = {
        normalize_dn(group_dn):
            group_dn

        for group_dn
        in current_groups
    }

    desired_normalized = {
        normalize_dn(group_dn):
            group_dn

        for group_dn
        in desired_group_dns
    }

    managed_birthright_dns = (
        get_all_managed_birthright_group_dns()
    )

    groups_to_add = []

    groups_to_remove = []

    # Desired groups missing from AD
    for normalized_dn, original_dn in (
        desired_normalized.items()
    ):

        if normalized_dn not in current_normalized:

            groups_to_add.append(
                original_dn
            )

    # Existing department groups no longer required
    for normalized_dn, original_dn in (
        current_normalized.items()
    ):

        if (
            normalized_dn
            in managed_birthright_dns

            and normalized_dn
            not in desired_normalized
        ):

            groups_to_remove.append(
                original_dn
            )

    return {
        "add":
            groups_to_add,

        "remove":
            groups_to_remove,
    }


# ============================================================
# JOINER Preparation
# ============================================================

def prepare_joiner(
    employee: Employee,
    ad_user: dict | None,
) -> dict:
    """
    Prepare a JOINER operation.

    Supports both:

    1. Normal JOINER
       Employee does not yet exist in Active Directory.

    2. Partial JOINER recovery
       Employee already exists in Active Directory with the
       same employeeID, is disabled, and is located in the
       expected target OU.

    Preparation performs no Active Directory writes.
    """

    employee_id = str(
        employee.employee_id
    ).strip()

    mapping = get_employee_identity_mapping(
        employee
    )

    target_ou = mapping["ou"]

    recovering_partial_joiner = False

    # ========================================================
    # Existing AD identity validation
    # ========================================================

    if ad_user:

        existing_employee_id = str(
            ad_user.get("employee_id")
            or ""
        ).strip()

        if existing_employee_id != employee_id:

            raise ValueError(
                (
                    f"JOINER preparation refused. "
                    f"Existing Active Directory identity "
                    f"does not match employeeID "
                    f"{employee_id}."
                )
            )

        if ad_user.get("enabled"):

            raise ValueError(
                (
                    f"JOINER preparation refused. "
                    f"Employee {employee_id} already exists "
                    f"in Active Directory and is enabled as "
                    f"{ad_user.get('distinguished_name')}."
                )
            )

        existing_dn = (
            ad_user.get("distinguished_name")
            or ""
        )

        if normalize_dn(target_ou) not in normalize_dn(
            existing_dn
        ):

            raise ValueError(
                (
                    f"JOINER recovery refused for employee "
                    f"{employee_id}. Existing AD account is "
                    f"not located in expected target OU "
                    f"{target_ou}. Found: {existing_dn}"
                )
            )

        recovering_partial_joiner = True

    # ========================================================
    # Manager resolution
    # ========================================================

    manager_employee_id = getattr(
        employee,
        "manager_employee_id",
        None,
    )

    if manager_employee_id is not None:
        manager_employee_id = (
            str(manager_employee_id).strip()
            or None
        )

    desired_manager_dn = None

    if manager_employee_id:
        if manager_employee_id == employee_id:
            raise ValueError(
                f"Employee {employee_id} cannot be "
                "assigned as their own manager."
            )

        manager_ad_user = (
            get_user_by_employee_id(
                manager_employee_id
            )
        )

        if not manager_ad_user:
            raise ValueError(
                f"Manager employee "
                f"{manager_employee_id} does not "
                "exist in Active Directory."
            )

        desired_manager_dn = (
            manager_ad_user.get(
                "distinguished_name"
            )
        )

        if not desired_manager_dn:
            raise RuntimeError(
                f"Manager employee "
                f"{manager_employee_id} does not "
                "have a distinguished name."
            )

    current_manager_dn = (
        ad_user.get("manager")
        if ad_user
        else None
    )

    manager_assignment_required = (
        normalize_dn(current_manager_dn)
        != normalize_dn(desired_manager_dn)
    )

    # ========================================================
    # Provisioning plan
    # ========================================================

    return {
        "operation":
            "CREATE_AD_USER",

        "employee_id":
            employee.employee_id,

        "desired_state":
            employee_snapshot(
                employee
            ),

        "identity_mapping": {
            "target_ou":
                target_ou,

            "birthright_groups":
                mapping["groups"],

            "birthright_group_dns":
                mapping["group_dns"],
        },

        "manager_change": {
            "old":
                current_manager_dn,

            "new":
                desired_manager_dn,

            "manager_employee_id":
                manager_employee_id,

            "assignment_required":
                manager_assignment_required,
        },

        "recovery": {
            "partial_joiner":
                recovering_partial_joiner,

            "existing_ad_user":
                ad_user
                if recovering_partial_joiner
                else None,
        },

        "ready_for_ad_write":
            True,

        "ad_write_executed":
            False,

        "execution_enabled":
            True,
    }




# ============================================================
# MOVER Preparation
# ============================================================

def prepare_mover(
    employee: Employee,
    ad_user: dict | None,
) -> dict:
    """
    Calculate exact MOVER changes.
    """

    if not ad_user:

        raise ValueError(
            (
                f"Employee {employee.employee_id} "
                "does not exist in Active Directory."
            )
        )

    desired_state = employee_snapshot(
        employee
    )

    mapping = get_employee_identity_mapping(
        employee
    )

    changes = {}

    # --------------------------------------------------------
    # Department
    # --------------------------------------------------------

    if (
        desired_state["department"]
        != ad_user.get("department")
    ):

        changes["department"] = {
            "old":
                ad_user.get("department"),

            "new":
                desired_state["department"],
        }

    # --------------------------------------------------------
    # Job title
    # --------------------------------------------------------

    if (
        desired_state["job_title"]
        != ad_user.get("title")
    ):

        changes["job_title"] = {
            "old":
                ad_user.get("title"),

            "new":
                desired_state["job_title"],
        }

    # --------------------------------------------------------
    # Email
    # --------------------------------------------------------

    if (
        desired_state["email"]
        != ad_user.get("email")
    ):

        changes["email"] = {
            "old":
                ad_user.get("email"),

            "new":
                desired_state["email"],
        }

    # --------------------------------------------------------
    # OU
    # --------------------------------------------------------

    # --------------------------------------------------------
    # Manager
    # --------------------------------------------------------

    current_manager_dn = ad_user.get("manager")

    manager_employee_id = getattr(
        employee,
        "manager_employee_id",
        None,
    )

    if manager_employee_id is not None:
        manager_employee_id = (
            str(manager_employee_id).strip()
            or None
        )

    desired_manager_dn = None

    if manager_employee_id:
        if manager_employee_id == str(employee.employee_id):
            raise ValueError(
                f"Employee {employee.employee_id} "
                "cannot be assigned as their own manager."
            )

        manager_ad_user = get_user_by_employee_id(
            manager_employee_id
        )

        if not manager_ad_user:
            raise ValueError(
                f"Manager employee {manager_employee_id} "
                "does not exist in Active Directory."
            )

        desired_manager_dn = manager_ad_user.get(
            "distinguished_name"
        )

        if not desired_manager_dn:
            raise RuntimeError(
                f"Manager employee {manager_employee_id} "
                "does not have a distinguished name."
            )

    if (
        normalize_dn(current_manager_dn)
        != normalize_dn(desired_manager_dn)
    ):
        changes["manager"] = {
            "old": current_manager_dn,
            "new": desired_manager_dn,
            "manager_employee_id": manager_employee_id,
        }

    # Keep manager changes separate from standard
    # user-attribute changes.
    standard_attribute_changes = {
        key: value
        for key, value in changes.items()
        if key != "manager"
    }

    current_dn = ad_user.get(
        "distinguished_name"
    )

    current_ou = get_parent_dn(
        current_dn
    )

    target_ou = mapping[
        "ou"
    ]

    ou_move_required = (
        normalize_dn(current_ou)
        != normalize_dn(target_ou)
    )

    # --------------------------------------------------------
    # Groups
    # --------------------------------------------------------

    group_changes = calculate_group_changes(
        current_groups=ad_user.get(
            "groups",
            [],
        ),
        desired_group_dns=mapping[
            "group_dns"
        ],
    )

    ready_for_ad_write = any(
        [
            bool(changes),
            ou_move_required,
            bool(group_changes["add"]),
            bool(group_changes["remove"]),
        ]
    )

    return {
        "operation":
            "UPDATE_AD_USER",

        "employee_id":
            employee.employee_id,

        "sam_account_name":
            ad_user.get(
                "sam_account_name"
            ),

        "ad_distinguished_name":
            current_dn,

        "current_ad_state":
            ad_user,

        "desired_state":
            desired_state,

        "identity_mapping": {
            "department":
                mapping["department"],

            "target_ou":
                target_ou,

            "birthright_groups":
                mapping["groups"],

            "birthright_group_dns":
                mapping["group_dns"],
        },

        "attribute_changes":
            changes,

        "standard_attribute_changes":
            standard_attribute_changes,

        "attribute_change_count":
            len(changes),

        "ou_change": {
            "current_ou":
                current_ou,

            "target_ou":
                target_ou,

            "move_required":
                ou_move_required,
        },

        "group_changes":
            group_changes,

        "planned_operations": {
            "update_attributes":
                bool(standard_attribute_changes),
            "update_manager":
                "manager" in changes,


            "move_user":
                ou_move_required,

            "remove_groups":
                bool(
                    group_changes["remove"]
                ),

            "add_groups":
                bool(
                    group_changes["add"]
                ),
        },

        "ready_for_ad_write":
            ready_for_ad_write,

        "ad_write_executed":
            False,

        "execution_enabled":
            True,
    }



# ============================================================
# LEAVER Preparation
# ============================================================


def prepare_leaver(
    employee: Employee,
    ad_user: dict | None,
) -> dict:
    """
    Calculate the exact idempotent LEAVER changes.

    Desired final state:
    - account disabled
    - direct group memberships removed
    - manager cleared
    - account moved to Disabled Users OU
    """

    if not ad_user:
        raise ValueError(
            f"Employee {employee.employee_id} "
            "does not exist in Active Directory."
        )

    if not AD_DISABLED_USERS_OU:
        raise ValueError(
            "AD_DISABLED_USERS_OU is not configured."
        )

    current_dn = ad_user.get("distinguished_name")
    current_ou = get_parent_dn(current_dn)

    groups_to_remove = list(
        ad_user.get("groups") or []
    )

    disable_required = (
        ad_user.get("enabled") is True
    )

    clear_manager_required = bool(
        ad_user.get("manager")
    )

    move_required = (
        normalize_dn(current_ou)
        != normalize_dn(AD_DISABLED_USERS_OU)
    )

    ready_for_ad_write = any(
        [
            disable_required,
            bool(groups_to_remove),
            clear_manager_required,
            move_required,
        ]
    )

    return {
        "operation": "DISABLE_AD_USER",
        "employee_id": employee.employee_id,
        "current_ad_state": ad_user,
        "groups_to_remove": groups_to_remove,
        "clear_manager": clear_manager_required,
        "target_ou": AD_DISABLED_USERS_OU,
        "planned_operations": {
            "disable_account": disable_required,
            "remove_groups": bool(groups_to_remove),
            "clear_manager": clear_manager_required,
            "move_user": move_required,
        },
        "ready_for_ad_write": ready_for_ad_write,
        "ad_write_executed": False,
        "execution_enabled": True,
    }



# ============================================================
# Prepare Request
# ============================================================

def prepare_identity_request_for_provisioning(
    request_id: str,
    db: Session,
) -> dict:
    """
    Prepare an approved lifecycle request.

    This function performs no AD writes.
    """

    request = get_identity_request(
        db=db,
        request_id=request_id,
    )

    validate_request_for_provisioning(
        request
    )

    employee = get_employee(
        db=db,
        employee_id=request.employee_id,
    )

    action = request.action.upper()

    connection_status = (
        test_ad_connection()
    )

    if not connection_status.get(
        "connected"
    ):

        raise RuntimeError(
            "Unable to connect to Active Directory."
        )

    ad_user = get_user_by_employee_id(
        employee.employee_id
    )

    if action == "JOINER":

        operation = prepare_joiner(
            employee,
            ad_user,
        )

    elif action == "MOVER":

        operation = prepare_mover(
            employee,
            ad_user,
        )

    elif action == "LEAVER":

        operation = prepare_leaver(
            employee,
            ad_user,
        )

    else:

        raise ValueError(
            f"Unsupported action: {action}"
        )

    create_audit_event(
        db=db,
        request=request,
        event_type="PROVISIONING_PREPARED",
        result="SUCCESS",
        details={
            "action":
                action,

            "approved_by":
                request.approved_by,

            "operation":
                operation,
        },
    )

    db.commit()

    return {
        "status":
            "ready",

        "request_id":
            request.request_id,

        "employee_id":
            request.employee_id,

        "action":
            action,

        "request_status":
            request.status,

        "approved_by":
            request.approved_by,

        "ad_connected":
            True,

        "operation":
            operation,

        "provisioning_started":
            False,

        "ad_write_executed":
            False,
    }


# ============================================================
# JOINER Execution
# ============================================================

def execute_joiner(
    employee: Employee,
    plan: dict,
) -> dict:
    """
    Execute an approved JOINER request against Active Directory.

    Supports:

    1. Normal JOINER
       - create AD account
       - assign birthright groups
       - set temporary password
       - require password change at next logon
       - enable account
       - verify final state

    2. Partial JOINER recovery
       - reuse matching disabled AD account
       - never recreate the identity
       - reconcile birthright groups idempotently
       - reset temporary password
       - require password change
       - enable account
       - verify final state

    The plaintext temporary password is never written to audit logs.
    """

    employee_id = str(employee.employee_id).strip()

    # ========================================================
    # Normalize provisioning plan
    # ========================================================

    if (
        isinstance(plan, dict)
        and isinstance(plan.get("desired_state"), dict)
    ):
        operation_data = plan

    elif (
        isinstance(plan, dict)
        and isinstance(plan.get("operation"), dict)
    ):
        operation_data = plan["operation"]

    else:
        raise ValueError(
            f"JOINER {employee_id}: invalid provisioning plan structure."
        )

    desired_state = operation_data.get(
        "desired_state",
        {},
    )

    identity_mapping = operation_data.get(
        "identity_mapping",
        {},
    )

    operation_name = operation_data.get(
        "operation"
    )

    if operation_name != "CREATE_AD_USER":
        raise ValueError(
            f"JOINER {employee_id}: expected CREATE_AD_USER operation, "
            f"found {operation_name!r}."
        )

    # ========================================================
    # Desired identity attributes
    # ========================================================

    first_name = desired_state.get("first_name")
    last_name = desired_state.get("last_name")
    department = desired_state.get("department")
    job_title = desired_state.get("job_title")
    email = desired_state.get("email")

    if not first_name:
        raise ValueError(
            f"JOINER {employee_id}: first_name is required."
        )

    if not last_name:
        raise ValueError(
            f"JOINER {employee_id}: last_name is required."
        )

    if not department:
        raise ValueError(
            f"JOINER {employee_id}: department is required."
        )

    # ========================================================
    # Identity mapping
    # ========================================================

    target_ou = identity_mapping.get(
        "target_ou"
    )

    birthright_group_dns = identity_mapping.get(
        "birthright_group_dns",
        [],
    )

    if not target_ou:
        raise ValueError(
            f"JOINER {employee_id}: no target OU mapping "
            f"exists for department '{department}'."
        )

    sam_account_name = (
        f"{first_name}.{last_name}"
        .strip()
        .lower()
        .replace(" ", "")
    )

    # ========================================================
    # Existing-account / partial-JOINER recovery boundary
    # ========================================================

    existing_user = get_user_by_employee_id(
        employee_id
    )

    recovering_partial_joiner = False

    if existing_user:

        existing_employee_id = str(
            existing_user.get("employee_id")
            or ""
        ).strip()

        if existing_employee_id != employee_id:
            raise RuntimeError(
                f"JOINER execution refused. "
                f"Existing AD identity does not match "
                f"employeeID {employee_id}."
            )

        if existing_user.get("enabled"):
            raise RuntimeError(
                f"JOINER execution refused. "
                f"Employee {employee_id} already exists "
                f"in Active Directory and is enabled as "
                f"{existing_user.get('distinguished_name')}."
            )

        existing_dn = (
            existing_user.get("distinguished_name")
            or ""
        )

        if normalize_dn(target_ou) not in normalize_dn(
            existing_dn
        ):
            raise RuntimeError(
                f"JOINER recovery refused for employee "
                f"{employee_id}. Existing AD account is not "
                f"located in expected target OU {target_ou}. "
                f"Found: {existing_dn}"
            )

        recovering_partial_joiner = True

    # ========================================================
    # Create account OR recover partial JOINER
    # ========================================================

    if recovering_partial_joiner:

        create_result = {
            "success": True,
            "employee_id": employee_id,
            "created": False,
            "recovered": True,
            "message": (
                "Existing disabled AD account accepted "
                "for partial JOINER recovery."
            ),
        }

    else:

        create_result = create_ad_user(
            employee_id=employee_id,
            first_name=first_name,
            last_name=last_name,
            department=department,
            job_title=job_title,
            email=email,
            target_ou=target_ou,
            sam_account_name=sam_account_name,
        )

    # ========================================================
    # Verify account exists before continuing
    # ========================================================

    created_user = get_user_by_employee_id(
        employee_id
    )

    if not created_user:
        raise RuntimeError(
            f"JOINER verification failed after account "
            f"creation/recovery. Employee {employee_id} "
            f"cannot be found in AD."
        )

    # ========================================================
    # Idempotent birthright-group assignment
    # ========================================================

    groups_added = []
    groups_already_present = []

    current_group_dns = {
        normalize_dn(group_dn)
        for group_dn in (
            created_user.get("groups", [])
            or []
        )
    }

    for group_dn in birthright_group_dns:

        normalized_group_dn = normalize_dn(
            group_dn
        )

        if normalized_group_dn in current_group_dns:
            groups_already_present.append(
                group_dn
            )
            continue

        result = add_user_to_group(
            employee_id=employee_id,
            group_dn=group_dn,
        )

        groups_added.append(
            result
        )

    # ========================================================
    # Manager assignment
    # ========================================================

    manager_change = operation_data.get(
        "manager_change",
        {},
    )

    manager_result = None

    if manager_change.get(
        "assignment_required"
    ):
        manager_result = set_ad_manager(
            employee_id=employee_id,
            manager_employee_id=(
                manager_change.get(
                    "manager_employee_id"
                )
            ),
        )

    # ========================================================
    # Temporary password provisioning
    # ========================================================

    temporary_password = (
        generate_temporary_password()
    )

    password_result = set_ad_password(
        employee_id=employee_id,
        password=temporary_password,
    )

    password_change_result = (
        require_password_change_at_next_logon(
            employee_id=employee_id,
        )
    )

    # ========================================================
    # Enable only after password setup succeeds
    # ========================================================

    enable_result = enable_ad_user(
        employee_id=employee_id
    )

    # ========================================================
    # Final AD verification
    # ========================================================

    verified_ad_state = get_user_by_employee_id(
        employee_id
    )

    if not verified_ad_state:
        raise RuntimeError(
            f"JOINER final verification failed. "
            f"Employee {employee_id} cannot be found in AD."
        )

    if not verified_ad_state.get("enabled"):
        raise RuntimeError(
            f"JOINER final verification failed for "
            f"employee {employee_id}. "
            f"AD account is still disabled."
        )

    final_dn = (
        verified_ad_state.get(
            "distinguished_name"
        )
        or ""
    )

    if (
        normalize_dn(target_ou)
        not in normalize_dn(final_dn)
    ):
        raise RuntimeError(
            f"JOINER OU verification failed for "
            f"employee {employee_id}. "
            f"Expected OU '{target_ou}', "
            f"found DN '{final_dn}'."
        )

    final_groups = {
        normalize_dn(group)
        for group in verified_ad_state.get(
            "groups",
            [],
        )
    }

    missing_groups = [
        group_dn
        for group_dn in birthright_group_dns
        if normalize_dn(group_dn)
        not in final_groups
    ]

    if missing_groups:
        raise RuntimeError(
            f"JOINER group verification failed for "
            f"employee {employee_id}. "
            f"Missing groups: {missing_groups}"
        )

    expected_manager_dn = (
        manager_change.get("new")
    )

    actual_manager_dn = (
        verified_ad_state.get("manager")
    )

    if (
        normalize_dn(actual_manager_dn)
        != normalize_dn(expected_manager_dn)
    ):
        raise RuntimeError(
            f"JOINER manager verification failed "
            f"for employee {employee_id}. "
            f"Expected: {expected_manager_dn}; "
            f"actual: {actual_manager_dn}"
        )

    # ========================================================
    # Return non-secret execution metadata
    #
    # IMPORTANT:
    # temporary_password is deliberately NOT returned because
    # execute_identity_request() records execution_result in
    # the provisioning audit event.
    # ========================================================

    return {
        "success": True,
        "employee_id": employee_id,
        "recovered_partial_joiner":
            recovering_partial_joiner,
        "account_creation":
            create_result,
        "groups_added":
            groups_added,
        "groups_already_present":
            groups_already_present,
        "manager_update":
            manager_result,

        "password_set":
            bool(password_result),
        "password_change_required":
            bool(password_change_result),
        "account_enablement":
            enable_result,
        "verified_ad_state":
            verified_ad_state,
    }




# ============================================================
# MOVER Execution
# ============================================================

def execute_mover(
    employee: Employee,
    plan: dict,
) -> dict:
    """
    Execute an approved, prepared MOVER against AD.

    Execution order:

        1. Update attributes
        2. Move user to target OU
        3. Remove obsolete birthright groups
        4. Add new birthright groups
        5. Read AD again for verification
    """

    employee_id = employee.employee_id

    results = {
        "attribute_update":
            None,

        "ou_move":
            None,

        "groups_removed":
            [],

        "groups_added":
            [],

        "manager_update":
            None,
    }

    planned = plan[
        "planned_operations"
    ]

    # ========================================================
    # 1. Update attributes
    # ========================================================

    if planned.get(
        "update_attributes"
    ):
        standard_changes = plan.get(
            "standard_attribute_changes",
            {},
        )

        department_value = (
            standard_changes["department"].get("new")
            if "department" in standard_changes
            else None
        )

        job_title_value = (
            standard_changes["job_title"].get("new")
            if "job_title" in standard_changes
            else None
        )

        email_value = (
            standard_changes["email"].get("new")
            if "email" in standard_changes
            else None
        )

        # Empty string clears an existing AD mail value.
        if (
            "email" in standard_changes
            and email_value is None
        ):
            email_value = ""

        results[
            "attribute_update"
        ] = update_ad_user(
            employee_id=employee_id,
            department=department_value,
            job_title=job_title_value,
            email=email_value,
        )

    # ========================================================
    # 2. Move OU
    # ========================================================

    # ========================================================
    # Manager assignment
    # ========================================================

    manager_change = (
        plan.get("attribute_changes", {})
        .get("manager")
    )

    if planned.get("update_manager"):
        results["manager_update"] = set_ad_manager(
            employee_id=employee_id,
            manager_employee_id=manager_change.get(
                "manager_employee_id"
            ),
        )

    target_ou = (
        plan[
            "identity_mapping"
        ][
            "target_ou"
        ]
    )

    if planned.get(
        "move_user"
    ):
        results[
            "ou_move"
        ] = move_ad_user(
            employee_id=employee_id,
            target_ou=target_ou,
        )

    # ========================================================
    # 3. Remove obsolete birthright groups
    # ========================================================

    for group_dn in (
        plan[
            "group_changes"
        ][
            "remove"
        ]
    ):

        result = (
            remove_user_from_group(
                employee_id=employee_id,
                group_dn=group_dn,
            )
        )

        results[
            "groups_removed"
        ].append(
            result
        )

    # ========================================================
    # 4. Add desired birthright groups
    # ========================================================

    for group_dn in (
        plan[
            "group_changes"
        ][
            "add"
        ]
    ):

        result = (
            add_user_to_group(
                employee_id=employee_id,
                group_dn=group_dn,
            )
        )

        results[
            "groups_added"
        ].append(
            result
        )

    # ========================================================
    # 5. Verify current AD state
    # ========================================================

    verified_state = (
        get_user_by_employee_id(
            employee_id
        )
    )

    if not verified_state:

        raise RuntimeError(
            (
                "MOVER operations completed but "
                "the AD account could not be "
                "retrieved for verification."
            )
        )

    if manager_change and (
        normalize_dn(verified_state.get("manager"))
        != normalize_dn(manager_change.get("new"))
    ):
        raise RuntimeError(
            "MOVER manager verification failed. "
            f"Expected: {manager_change.get('new')}; "
            f"Actual: {verified_state.get('manager')}"
        )

    attribute_key_mapping = {
        "department": "department",
        "job_title": "title",
        "email": "email",
    }

    for change_name, change in plan.get(
        "standard_attribute_changes",
        {},
    ).items():
        ad_key = attribute_key_mapping[
            change_name
        ]

        expected_value = change.get("new")
        actual_value = verified_state.get(ad_key)

        normalized_expected = (
            ""
            if expected_value is None
            else str(expected_value).strip()
        )

        normalized_actual = (
            ""
            if actual_value is None
            else str(actual_value).strip()
        )

        if normalized_actual != normalized_expected:
            raise RuntimeError(
                f"MOVER {change_name} verification "
                f"failed. Expected: {expected_value}; "
                f"actual: {actual_value}"
            )

    verified_ou = get_parent_dn(
        verified_state.get(
            "distinguished_name"
        )
    )

    if (
        normalize_dn(verified_ou)
        != normalize_dn(target_ou)
    ):
        raise RuntimeError(
            "MOVER OU verification failed. "
            f"Expected: {target_ou}; "
            f"actual: {verified_ou}"
        )

    verified_groups = {
        normalize_dn(group_dn)
        for group_dn in (
            verified_state.get("groups")
            or []
        )
    }

    missing_groups = [
        group_dn
        for group_dn in plan[
            "identity_mapping"
        ][
            "birthright_group_dns"
        ]
        if normalize_dn(group_dn)
        not in verified_groups
    ]

    obsolete_groups = [
        group_dn
        for group_dn in plan[
            "group_changes"
        ][
            "remove"
        ]
        if normalize_dn(group_dn)
        in verified_groups
    ]

    if missing_groups or obsolete_groups:
        raise RuntimeError(
            "MOVER group verification failed. "
            f"Missing groups: {missing_groups}; "
            f"obsolete groups: {obsolete_groups}"
        )

    results[
        "verified_ad_state"
    ] = verified_state

    return results



# ============================================================
# Execute Approved Identity Request
# ============================================================

# ============================================================
# LEAVER Execution
# ============================================================

def execute_leaver(
    employee: Employee,
    plan: dict,
) -> dict:
    """
    Execute and verify an idempotent LEAVER operation.

    Order:
    1. Disable account
    2. Remove direct groups
    3. Clear manager
    4. Move to Disabled Users
    5. Verify final AD state
    """

    employee_id = str(employee.employee_id).strip()
    planned = plan.get("planned_operations", {})
    target_ou = plan.get("target_ou")

    if not target_ou:
        raise ValueError(
            f"LEAVER {employee_id}: target OU is missing."
        )

    results = {
        "success": True,
        "employee_id": employee_id,
        "account_disablement": None,
        "groups_removed": [],
        "manager_clear": None,
        "ou_move": None,
    }

    # Disable first to contain access immediately.
    if planned.get("disable_account"):
        results["account_disablement"] = (
            disable_ad_user(
                employee_id=employee_id,
            )
        )

    for group_dn in plan.get(
        "groups_to_remove",
        [],
    ):
        result = remove_user_from_group(
            employee_id=employee_id,
            group_dn=group_dn,
        )

        results["groups_removed"].append(result)

    if planned.get("clear_manager"):
        results["manager_clear"] = (
            set_ad_manager(
                employee_id=employee_id,
                manager_employee_id=None,
            )
        )

    if planned.get("move_user"):
        results["ou_move"] = move_ad_user(
            employee_id=employee_id,
            target_ou=target_ou,
        )

    verified_state = get_user_by_employee_id(
        employee_id
    )

    if not verified_state:
        raise RuntimeError(
            f"LEAVER verification failed. Employee "
            f"{employee_id} cannot be found in AD."
        )

    if verified_state.get("enabled") is not False:
        raise RuntimeError(
            f"LEAVER verification failed for "
            f"{employee_id}: account is still enabled."
        )

    if verified_state.get("manager"):
        raise RuntimeError(
            f"LEAVER verification failed for "
            f"{employee_id}: manager was not cleared."
        )

    remaining_groups = list(
        verified_state.get("groups") or []
    )

    if remaining_groups:
        raise RuntimeError(
            f"LEAVER verification failed for "
            f"{employee_id}: groups remain: "
            f"{remaining_groups}"
        )

    verified_ou = get_parent_dn(
        verified_state.get("distinguished_name")
    )

    if (
        normalize_dn(verified_ou)
        != normalize_dn(target_ou)
    ):
        raise RuntimeError(
            f"LEAVER OU verification failed for "
            f"{employee_id}. Expected: {target_ou}; "
            f"actual: {verified_ou}"
        )

    results["verified_ad_state"] = verified_state

    return results


def execute_identity_request(
    request_id: str,
    db: Session,
) -> dict:
    """
    Execute an Approved IdentityRequest.

    CURRENT EXECUTION SUPPORT:

        JOINER = enabled
        MOVER  = enabled
        LEAVER = enabled

    Request lifecycle:

        Approved
            ↓
        Provisioning
            ↓
        Active Directory
            ↓
        Verification
            ↓
        Completed

    Failure:

        Provisioning
            ↓
        Failed
    """

    request = get_identity_request(
        db=db,
        request_id=request_id,
    )

    validate_request_for_provisioning(
        request
    )

    employee = get_employee(
        db=db,
        employee_id=request.employee_id,
    )

    action = request.action.upper()

    # ========================================================
    # Execution support boundary
    # ========================================================

    if action not in {
        "JOINER",
        "MOVER",
        "LEAVER",
    }:
        raise ValueError(
            (
                f"{action} execution is not enabled. "
                "JOINER, MOVER, and LEAVER are enabled."
            )
        )

    # ========================================================
    # Prepare exact plan
    # ========================================================

    ad_user = get_user_by_employee_id(
        employee.employee_id
    )

    if action == "JOINER":
        plan = prepare_joiner(
            employee=employee,
            ad_user=ad_user,
        )

    elif action == "MOVER":
        plan = prepare_mover(
            employee=employee,
            ad_user=ad_user,
        )

    elif action == "LEAVER":
        plan = prepare_leaver(
            employee=employee,
            ad_user=ad_user,
        )

    else:
        raise ValueError(
            f"Unsupported execution action: {action}"
        )

    if not plan.get(
        "execution_enabled",
        False,
    ):
        raise ValueError(
            (
                f"{action} execution is disabled "
                "in the provisioning plan."
            )
        )

    # An approved request whose desired state is already
    # satisfied is a successful idempotent completion.
    if not plan["ready_for_ad_write"]:
        request.status = "Completed"
        request.completed_at = datetime.utcnow()

        execution_result = {
            "success": True,
            "changed": False,
            "message": (
                "Desired Active Directory state was "
                "already satisfied."
            ),
            "verified_ad_state": (
                plan.get("current_ad_state")
                or ad_user
            ),
        }

        create_audit_event(
            db=db,
            request=request,
            event_type="PROVISIONING_NO_CHANGE",
            result="SUCCESS",
            details={
                "action": action,
                "approved_by": request.approved_by,
                "plan": plan,
            },
        )

        db.commit()
        db.refresh(request)

        return {
            "status": "success",
            "message": (
                f"{action} request completed; desired "
                "AD state was already satisfied"
            ),
            "request_id": request.request_id,
            "employee_id": employee.employee_id,
            "action": action,
            "request_status": request.status,
            "approved_by": request.approved_by,
            "completed_at": request.completed_at,
            "ad_write_executed": False,
            "execution_result": execution_result,
        }

    # ========================================================
    # Mark Provisioning
    # ========================================================

    request.status = (
        "Provisioning"
    )

    create_audit_event(
        db=db,
        request=request,
        event_type="PROVISIONING_STARTED",
        result="STARTED",
        details={
            "action":
                action,

            "approved_by":
                request.approved_by,

            "plan":
                plan,
        },
    )

    db.commit()

    try:

        # ====================================================
        # Execute AD changes
        # ====================================================

        if action == "JOINER":
            execution_result = execute_joiner(
                employee=employee,
                plan=plan,
            )

        elif action == "MOVER":
            execution_result = execute_mover(
                employee=employee,
                plan=plan,
            )

        elif action == "LEAVER":
            execution_result = execute_leaver(
                employee=employee,
                plan=plan,
            )

        else:
            raise ValueError(
                f"Unsupported execution action: {action}"
            )

        # ====================================================
        # Mark Completed
        # ====================================================

        request.status = (
            "Completed"
        )

        request.completed_at = (
            datetime.utcnow()
        )

        create_audit_event(
            db=db,
            request=request,
            event_type="PROVISIONING_COMPLETED",
            result="SUCCESS",
            details={
                "action":
                    action,

                "approved_by":
                    request.approved_by,

                "execution_result":
                    execution_result,
            },
        )

        db.commit()

        db.refresh(
            request
        )

        return {
            "status":
                "success",

            "message":
                f"{action} provisioning completed successfully",

            "request_id":
                request.request_id,

            "employee_id":
                employee.employee_id,

            "action":
                action,

            "request_status":
                request.status,

            "approved_by":
                request.approved_by,

            "completed_at":
                request.completed_at,

            "ad_write_executed":
                True,

            "execution_result":
                execution_result,
        }

    except Exception as exc:

        # ====================================================
        # Roll back pending DB transaction
        # ====================================================

        db.rollback()

        # Reload request after rollback
        request = get_identity_request(
            db=db,
            request_id=request_id,
        )

        request.status = (
            "Failed"
        )

        create_audit_event(
            db=db,
            request=request,
            event_type="PROVISIONING_FAILED",
            result="FAILED",
            details={
                "action":
                    action,

                "error":
                    str(exc),
            },
        )

        db.commit()

        raise RuntimeError(
            (
                f"{action} provisioning failed "
                f"for request {request_id}: "
                f"{exc}"
            )
        ) from exc

