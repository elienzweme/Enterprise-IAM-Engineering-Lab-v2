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
    reconcile_ad_identity,
    test_ad_connection,
    create_ad_user,
    update_ad_user,
    generate_temporary_password,
    set_ad_password,
    require_password_change_at_next_logon,
    enable_ad_user,
    move_ad_user,
    add_user_to_group,
    remove_user_from_group,
    set_ad_manager,
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
# Secret Redaction
# ============================================================

SENSITIVE_KEYS = {
    "password",
    "temporary_password",
    "credential",
    "secret",
    "token",
    "access_token",
    "refresh_token",
}


def redact_secrets(value):
    """
    Recursively redact secrets before writing audit details.

    The JOINER response may contain a one-time temporary password,
    but AuditEvent.details must never persist it.
    """
    if isinstance(value, dict):
        sanitized = {}

        for key, item in value.items():
            if str(key).lower() in SENSITIVE_KEYS:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = redact_secrets(item)

        return sanitized

    if isinstance(value, list):
        return [
            redact_secrets(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            redact_secrets(item)
            for item in value
        )

    return value


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
            redact_secrets(details),
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

    if request.status != "Approved":

        raise ValueError(
            (
                f"Request {request.request_id} "
                f"has status '{request.status}'. "
                "Only Approved requests can be provisioned."
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
    correlation: dict,
) -> dict:
    """
    Prepare a JOINER as either a new account or a safe adoption/reconciliation
    of an existing legacy account.
    """
    mapping = get_employee_identity_mapping(employee)
    ad_user = correlation.get("ad_user")
    adopted = bool(ad_user)

    return {
        "operation": (
            "ADOPT_EXISTING_AD_USER"
            if adopted
            else "CREATE_AD_USER"
        ),
        "employee_id": employee.employee_id,
        "desired_state": employee_snapshot(employee),
        "identity_mapping": {
            "target_ou": mapping["ou"],
            "birthright_groups": mapping["groups"],
            "birthright_group_dns": mapping["group_dns"],
        },
        "correlation": {
            "method": correlation.get("correlation_method"),
            "employee_id_backfilled": correlation.get("employee_id_backfilled", False),
            "legacy_account_adopted": correlation.get("legacy_account_adopted", False),
            "sam_account_name": correlation.get("sam_account_name"),
        },
        "current_ad_state": ad_user,
        "preserve_existing_password": adopted,
        "ready_for_ad_write": True,
        "ad_write_executed": False,
        "execution_enabled": True,
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
                bool(changes),

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
    Prepare LEAVER operation.

    LEAVER execution is intentionally not enabled yet.
    """

    if not ad_user:

        raise ValueError(
            (
                f"Employee {employee.employee_id} "
                "does not exist in Active Directory."
            )
        )

    return {
        "operation":
            "DISABLE_AD_USER",

        "employee_id":
            employee.employee_id,

        "current_ad_state":
            ad_user,

        "ready_for_ad_write":
            True,

        "ad_write_executed":
            False,

        "execution_enabled":
            False,
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

    if action == "JOINER":
        correlation = reconcile_ad_identity(
            employee_id=employee.employee_id,
            first_name=employee.first_name,
            last_name=employee.last_name,
        )
        ad_user = correlation.get("ad_user")
        operation = prepare_joiner(
            employee,
            correlation,
        )

    elif action == "MOVER":
        ad_user = get_user_by_employee_id(employee.employee_id)

        operation = prepare_mover(
            employee,
            ad_user,
        )

    elif action == "LEAVER":
        ad_user = get_user_by_employee_id(employee.employee_id)

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

    Execution flow:
        1. Normalize/validate the approved provisioning plan
        2. Create the user disabled OR safely resume a partial JOINER
        3. Generate a cryptographically random temporary password
        4. Set the password over LDAPS
        5. Require password change at next logon
        6. Add birthright group memberships
        7. Enable the account
        8. Read the account back and verify final state

    The temporary password is returned ONCE to the caller and is
    automatically redacted from AuditEvent.details.
    """

    employee_id = str(employee.employee_id)

    # ---------------------------------------------------------
    # Normalize the provisioning plan
    # ---------------------------------------------------------

    if (
        isinstance(plan, dict)
        and isinstance(
            plan.get("desired_state"),
            dict,
        )
    ):
        operation_data = plan

    elif (
        isinstance(plan, dict)
        and isinstance(
            plan.get("operation"),
            dict,
        )
    ):
        operation_data = plan[
            "operation"
        ]

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

    if operation_name not in {"CREATE_AD_USER", "ADOPT_EXISTING_AD_USER"}:
        raise ValueError(
            f"JOINER {employee_id}: unsupported operation {operation_name!r}."
        )

    adopting_existing = operation_name == "ADOPT_EXISTING_AD_USER"

    # ---------------------------------------------------------
    # Desired identity
    # ---------------------------------------------------------

    first_name = desired_state.get(
        "first_name"
    )

    last_name = desired_state.get(
        "last_name"
    )

    department = desired_state.get(
        "department"
    )

    job_title = desired_state.get(
        "job_title"
    )

    email = desired_state.get(
        "email"
    )

    # manager_employee_id should be the HR employeeId of the supervisor.
    # For backward compatibility, a manager value that looks like an
    # employee ID is also accepted.
    manager_employee_id = desired_state.get("manager_employee_id")
    if not manager_employee_id:
        manager_value = desired_state.get("manager")
        if manager_value and str(manager_value).strip().isdigit():
            manager_employee_id = str(manager_value).strip()

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

    target_ou = identity_mapping.get(
        "target_ou"
    )

    birthright_group_dns = (
        identity_mapping.get(
            "birthright_group_dns",
            [],
        )
    )

    if not target_ou:
        raise ValueError(
            f"JOINER {employee_id}: no target OU mapping exists "
            f"for department '{department}'."
        )

    # ---------------------------------------------------------
    # firstname.lastname
    # ---------------------------------------------------------

    sam_account_name = (
        f"{first_name}.{last_name}"
        .strip()
        .lower()
        .replace(" ", "")
    )

    # ---------------------------------------------------------
    # Create, adopt, or resume
    # ---------------------------------------------------------

    existing_user = get_user_by_employee_id(employee_id)

    if adopting_existing:
        if not existing_user:
            raise RuntimeError(
                f"JOINER adoption failed for employee {employee_id}: "
                "the correlated AD account can no longer be found."
            )

        sam_account_name = existing_user.get("sam_account_name") or sam_account_name

        create_result = {
            "success": True,
            "operation": "ADOPT_EXISTING_AD_USER",
            "employee_id": employee_id,
            "creation_skipped": True,
            "existing_account_preserved": True,
            "password_preserved": True,
            "distinguished_name": existing_user.get("distinguished_name"),
            "sam_account_name": sam_account_name,
        }

        # Reconcile ordinary HR-controlled attributes.
        update_ad_user(
            employee_id=employee_id,
            department=department,
            job_title=job_title,
            email=email,
        )

        current_dn = existing_user.get("distinguished_name")
        if normalize_dn(get_parent_dn(current_dn)) != normalize_dn(target_ou):
            move_ad_user(employee_id=employee_id, target_ou=target_ou)

    elif existing_user:
        existing_sam = existing_user.get("sam_account_name") or ""

        if existing_sam.lower() != sam_account_name.lower():
            raise RuntimeError(
                f"JOINER recovery refused for employee {employee_id}. "
                f"Expected account '{sam_account_name}', but AD contains "
                f"'{existing_sam}'. Manual review is required."
            )

        if existing_user.get("enabled"):
            raise RuntimeError(
                f"JOINER recovery refused for employee {employee_id}. "
                "Existing account is enabled; manual review is required."
            )

        create_result = {
            "success": True,
            "operation": "CREATE_AD_USER",
            "employee_id": employee_id,
            "resumed_partial_joiner": True,
            "creation_skipped": True,
            "distinguished_name": existing_user.get("distinguished_name"),
            "sam_account_name": existing_sam,
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

    # ---------------------------------------------------------
    # Verify user exists
    # ---------------------------------------------------------

    created_user = get_user_by_employee_id(
        employee_id
    )

    if not created_user:
        raise RuntimeError(
            f"JOINER verification failed after account creation/recovery. "
            f"Employee {employee_id} cannot be found in AD."
        )

    # ---------------------------------------------------------
    # Password handling
    # ---------------------------------------------------------

    temporary_password = None
    password_result = None
    password_change_result = None

    if not adopting_existing:
        temporary_password = generate_temporary_password()

        password_result = set_ad_password(
            employee_id=employee_id,
            password=temporary_password,
        )

        password_change_result = require_password_change_at_next_logon(
            employee_id=employee_id,
        )

    # ---------------------------------------------------------
    # Add birthright groups
    # ---------------------------------------------------------

    groups_added = []

    for group_dn in birthright_group_dns:
        result = add_user_to_group(
            employee_id=employee_id,
            group_dn=group_dn,
        )

        groups_added.append(
            result
        )

    # ---------------------------------------------------------
    # Enable account only after password + groups succeed
    # ---------------------------------------------------------

    if adopting_existing:
        enable_result = {
            "success": True,
            "changed": False,
            "preserved_existing_state": True,
            "enabled": created_user.get("enabled"),
        }
    else:
        enable_result = enable_ad_user(
            employee_id=employee_id
        )

    # ---------------------------------------------------------
    # Manager assignment
    # ---------------------------------------------------------

    manager_result = None
    if manager_employee_id:
        manager_ad_user = get_user_by_employee_id(str(manager_employee_id))
        if manager_ad_user:
            manager_result = set_ad_manager(
                employee_id=employee_id,
                manager_employee_id=str(manager_employee_id),
            )
        else:
            # Do not fail a valid JOINER only because the supervisor has not
            # been provisioned yet. A later synchronization can apply it.
            manager_result = {
                "success": False,
                "deferred": True,
                "manager_employee_id": str(manager_employee_id),
                "message": "Manager is not yet present in Active Directory; assignment deferred.",
            }

    # ---------------------------------------------------------
    # Final verification
    # ---------------------------------------------------------

    verified_ad_state = (
        get_user_by_employee_id(
            employee_id
        )
    )

    if not verified_ad_state:
        raise RuntimeError(
            f"JOINER final verification failed. "
            f"Employee {employee_id} cannot be found in AD."
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
            f"JOINER OU verification failed for employee {employee_id}. "
            f"Expected OU '{target_ou}', found DN '{final_dn}'."
        )

    final_groups = {
        normalize_dn(group)
        for group in (
            verified_ad_state.get(
                "groups",
                [],
            )
        )
    }

    missing_groups = [
        group_dn
        for group_dn
        in birthright_group_dns
        if (
            normalize_dn(group_dn)
            not in final_groups
        )
    ]

    if missing_groups:
        raise RuntimeError(
            f"JOINER group verification failed for employee "
            f"{employee_id}. Missing groups: {missing_groups}"
        )

    if (
        not adopting_existing
        and verified_ad_state.get(
            "enabled"
        )
        is not True
    ):
        raise RuntimeError(
            f"JOINER enablement verification failed for "
            f"employee {employee_id}."
        )

    return {
        "employee_id":
            employee_id,

        "sam_account_name":
            sam_account_name,

        "user_principal_name":
            verified_ad_state.get(
                "user_principal_name"
            ),

        # IMPORTANT:
        # This secret is intended to be shown once to the authorized
        # operator/secure-delivery service. create_audit_event()
        # redacts it before persistence.
        "temporary_password":
            temporary_password,

        "must_change_password_at_next_logon":
            (not adopting_existing),

        "target_ou":
            target_ou,

        "create_user":
            create_result,

        "password_set":
            password_result,

        "password_change_required":
            password_change_result,

        "groups_added":
            groups_added,

        "enable_result":
            enable_result,

        "verified_ad_state":
            verified_ad_state,

        "success":
            True,
        "adopted_existing_account": adopting_existing,
        "manager_result": manager_result,
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

        results[
            "attribute_update"
        ] = update_ad_user(
            employee_id=employee_id,
            department=employee.department,
            job_title=employee.job_title,
            email=employee.email,
        )

    # ========================================================
    # 2. Move OU
    # ========================================================

    if planned.get(
        "move_user"
    ):

        target_ou = (
            plan[
                "identity_mapping"
            ][
                "target_ou"
            ]
        )

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

    results[
        "verified_ad_state"
    ] = verified_state

    return results


# ============================================================
# Execute Approved Identity Request
# ============================================================

def execute_identity_request(
    request_id: str,
    db: Session,
) -> dict:
    """
    Execute an Approved IdentityRequest.

    CURRENT EXECUTION SUPPORT:

        JOINER = enabled
        MOVER  = enabled
        LEAVER = preparation only

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
    }:
        raise ValueError(
            (
                f"{action} execution is not enabled yet. "
                "JOINER and MOVER are currently enabled."
            )
        )

    # ========================================================
    # Prepare exact plan
    # ========================================================

    if action == "JOINER":
        correlation = reconcile_ad_identity(
            employee_id=employee.employee_id,
            first_name=employee.first_name,
            last_name=employee.last_name,
        )

        plan = prepare_joiner(
            employee=employee,
            correlation=correlation,
        )

    elif action == "MOVER":
        ad_user = get_user_by_employee_id(
            employee.employee_id
        )

        plan = prepare_mover(
            employee=employee,
            ad_user=ad_user,
        )

    else:
        raise ValueError(
            f"Unsupported execution action: {action}"
        )

    if not plan[
        "ready_for_ad_write"
    ]:
        raise ValueError(
            (
                "No Active Directory changes "
                "are required for this request."
            )
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

