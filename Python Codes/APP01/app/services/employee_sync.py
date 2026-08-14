# app/services/employee_sync.py

import json
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.models import (
    Employee,
    IdentityRequest,
    AuditEvent,
)

from app.services.orangehrm import (
    get_employees,
    get_employee_job_details,
    resolve_employee_supervisor,
)

from app.services.ad_service import (
    get_user_by_employee_id,
    reconcile_ad_identity,
)

from app.config.identity_scope import (
    DEPARTMENT_GROUP_MAPPING,
)


# ============================================================
# LAB SAFETY EXCLUSIONS
# ============================================================
#
# Employee 0001 is currently your OrangeHRM administrative
# identity. We do not want the IAM JML engine treating this
# account as a normal HR-controlled employee.
#
# Remove this exclusion later if 0001 becomes a real
# lifecycle-managed employee.
#
# ============================================================

EXCLUDED_HR_EMPLOYEE_IDS = {
    "0001",
}


# ============================================================
# LIFECYCLE ATTRIBUTES
# ============================================================
#
# Changes to these attributes can generate a MOVER request.
#
# ============================================================

MOVER_ATTRIBUTES = (
    "department",
    "job_title",
    "manager",
    "employment_status",
)


# ============================================================
# RBAC
# ============================================================

def get_birthright_group(
    department: str | None,
) -> str | None:
    """
    Return the department birthright AD group.

    Privileged groups are intentionally not assigned here.
    """

    if not department:
        return None

    return DEPARTMENT_GROUP_MAPPING.get(
        department
    )


# ============================================================
# DATA EXTRACTION HELPERS
# ============================================================

def _extract_name(value):
    """
    OrangeHRM sometimes returns an attribute directly as a
    string and sometimes as a dictionary such as:

        {"id": 1, "name": "IT"}

    Normalize either representation to a string.
    """

    if value is None:
        return None

    if isinstance(value, str):
        return value.strip() or None

    if isinstance(value, dict):
        for key in (
            "name",
            "label",
            "title",
        ):
            result = value.get(key)

            if result:
                return str(result).strip()

    return None


def _first_present(
    data: dict,
    *keys,
):
    """
    Return the first existing non-empty value.
    """

    for key in keys:
        value = data.get(key)

        if value not in (
            None,
            "",
            [],
            {},
        ):
            return value

    return None


def _normalize_text(
    value,
) -> str | None:
    """
    Normalize a value for safe comparison.
    """

    if value is None:
        return None

    result = str(value).strip()

    return result or None


def _normalize_dn(
    value,
) -> str | None:
    """
    Normalize an Active Directory distinguished name for
    case-insensitive comparison.
    """

    value = _normalize_text(value)

    if value is None:
        return None

    return value.lower()


# ============================================================
# ORANGEHRM JOB DATA NORMALIZATION
# ============================================================

def normalize_job_details(
    payload: dict,
) -> dict:
    """
    Convert OrangeHRM job-details JSON into IAM attributes.

    Supervisor information is resolved separately using the
    OrangeHRM /supervisors endpoint because job-details does
    not reliably include the employee's manager.
    """

    data = payload.get(
        "data",
        {},
    )

    if not isinstance(data, dict):
        data = {}

    # --------------------------------------------------------
    # Department
    # --------------------------------------------------------

    department_raw = _first_present(
        data,
        "department",
        "subunit",
    )

    department = _extract_name(
        department_raw
    )

    # --------------------------------------------------------
    # Job Title
    # --------------------------------------------------------

    job_title_raw = _first_present(
        data,
        "jobTitle",
        "job_title",
    )

    job_title = _extract_name(
        job_title_raw
    )

    # --------------------------------------------------------
    # Employment Status
    # --------------------------------------------------------

    employment_status_raw = _first_present(
        data,
        "empStatus",
        "employmentStatus",
        "employment_status",
    )

    employment_status = _extract_name(
        employment_status_raw
    )

    # --------------------------------------------------------
    # Email
    # --------------------------------------------------------

    email = _first_present(
        data,
        "email",
        "workEmail",
        "work_email",
    )

    if isinstance(email, str):
        email = email.strip() or None
    else:
        email = None

    return {
        "department": department,
        "job_title": job_title,
        "employment_status": employment_status,
        "manager": None,
        "manager_employee_id": None,
        "email": email,
    }


# ============================================================
# REQUEST HELPERS
# ============================================================

def generate_request_id(
    action: str,
) -> str:
    """
    Generate unique lifecycle request ID.

    Example:

        JOINER-a12b34c5
    """

    return (
        f"{action.upper()}-"
        f"{uuid.uuid4().hex[:8]}"
    )


def pending_request_exists(
    db: Session,
    employee_id: str,
    action: str,
) -> bool:
    """
    Prevent duplicate pending lifecycle requests.
    """

    existing = (
        db.query(IdentityRequest)
        .filter(
            IdentityRequest.employee_id
            == employee_id,
            IdentityRequest.action
            == action,
            IdentityRequest.status
            == "Pending",
        )
        .first()
    )

    return existing is not None


def create_identity_request(
    db: Session,
    employee_id: str,
    action: str,
) -> IdentityRequest | None:
    """
    Stage a Joiner/Mover/Leaver request.

    This function DOES NOT modify Active Directory.
    """

    if pending_request_exists(
        db,
        employee_id,
        action,
    ):
        return None

    request = IdentityRequest(
        request_id=generate_request_id(
            action
        ),
        employee_id=employee_id,
        action=action,
        status="Pending",
        requested_by="OrangeHRM Sync",
    )

    db.add(request)

    return request


# ============================================================
# AUDIT HELPERS
# ============================================================

def create_audit_event(
    db: Session,
    employee_id: str,
    event_type: str,
    result: str,
    details: dict,
    request_id: str | None = None,
):
    """
    Write lifecycle activity into IAM audit_events.
    """

    event = AuditEvent(
        request_id=request_id,
        employee_id=employee_id,
        event_type=event_type,
        system="OrangeHRM",
        result=result,
        details=json.dumps(
            details,
            default=str,
        ),
        timestamp=datetime.utcnow(),
    )

    db.add(event)


# ============================================================
# CHANGE DETECTION
# ============================================================

def detect_mover_changes(
    existing: Employee,
    incoming: dict,
) -> dict:
    """
    Compare authoritative HR attributes against current IAM
    employee attributes.

    Returns only attributes that changed.
    """

    changes = {}

    for attribute in MOVER_ATTRIBUTES:
        old_value = getattr(
            existing,
            attribute,
        )

        new_value = incoming.get(
            attribute
        )

        # Do not overwrite existing values merely because an
        # OrangeHRM endpoint did not provide the field.
        if new_value is None:
            continue

        if old_value != new_value:
            changes[attribute] = {
                "old": old_value,
                "new": new_value,
            }

    return changes


def detect_ad_reconciliation_changes(
    ad_user: dict | None,
    incoming: dict,
) -> dict:
    """
    Compare OrangeHRM-authoritative identity attributes with an
    already-existing AD account.

    This is used when the employee already exists in AD, so a
    JOINER must never be created for the same employeeID.

    Manager comparison is performed using the manager's AD DN
    whenever the supervisor's employeeId can be resolved.
    """

    if not ad_user:
        return {}

    changes = {}

    desired_department = incoming.get(
        "department"
    )

    current_department = ad_user.get(
        "department"
    )

    if (
        desired_department is not None
        and _normalize_text(desired_department)
        != _normalize_text(current_department)
    ):
        changes["department"] = {
            "old": current_department,
            "new": desired_department,
        }

    desired_title = incoming.get(
        "job_title"
    )

    current_title = ad_user.get(
        "title"
    )

    if (
        desired_title is not None
        and _normalize_text(desired_title)
        != _normalize_text(current_title)
    ):
        changes["job_title"] = {
            "old": current_title,
            "new": desired_title,
        }

    manager_employee_id = incoming.get(
        "manager_employee_id"
    )

    if manager_employee_id:
        manager_ad_user = (
            get_user_by_employee_id(
                str(manager_employee_id)
            )
        )

        if manager_ad_user:
            desired_manager_dn = (
                manager_ad_user.get(
                    "distinguished_name"
                )
            )

            current_manager_dn = (
                ad_user.get(
                    "manager"
                )
            )

            if (
                desired_manager_dn
                and _normalize_dn(
                    desired_manager_dn
                )
                != _normalize_dn(
                    current_manager_dn
                )
            ):
                changes["manager"] = {
                    "old": current_manager_dn,
                    "new": desired_manager_dn,
                    "manager_employee_id":
                        str(manager_employee_id),
                    "manager_name":
                        incoming.get("manager"),
                }

    return changes


# ============================================================
# EMPLOYEE UPDATE
# ============================================================

def update_employee_record(
    employee: Employee,
    incoming: dict,
):
    """
    Update IAM employee attributes using HR-authoritative
    values.

    None values do not erase existing enrichment data.
    """

    employee.first_name = (
        incoming.get("first_name")
        or employee.first_name
    )

    employee.last_name = (
        incoming.get("last_name")
        or employee.last_name
    )

    if incoming.get("email") is not None:
        employee.email = incoming["email"]

    if incoming.get("department") is not None:
        employee.department = (
            incoming["department"]
        )

    if incoming.get("job_title") is not None:
        employee.job_title = (
            incoming["job_title"]
        )

    if incoming.get("manager") is not None:
        employee.manager = (
            incoming["manager"]
        )

    if (
        incoming.get(
            "employment_status"
        )
        is not None
    ):
        employee.employment_status = (
            incoming[
                "employment_status"
            ]
        )

    employee.source_system = (
        "OrangeHRM"
    )

    employee.updated_at = (
        datetime.utcnow()
    )


# ============================================================
# MAIN ORANGEHRM SYNCHRONIZATION
# ============================================================

def sync_orangehrm_employees(
    access_token: str,
    db: Session,
):
    """
    Synchronize OrangeHRM into the IAM database.

    Responsibilities:

    1. Retrieve employees from OrangeHRM.
    2. Enrich each employee using job-details.
    3. Resolve supervisor empNumber -> employeeId.
    4. Correlate the identity against Active Directory using
       AD employeeID.
    5. Detect Joiner/Mover/Leaver lifecycle conditions.
    6. Update the IAM employee record.
    7. Stage IdentityRequest records.
    8. Write AuditEvent records.

    IMPORTANT:

    This function DOES NOT provision Active Directory.

    AD changes happen only after the staged IdentityRequest
    is processed by the provisioning workflow.

    Duplicate-protection rule:

        HR employeeId exists in AD
            -> never create a JOINER

        HR employeeId does not exist in AD
            -> JOINER may be staged

    This makes employeeId the correlation key across:

        OrangeHRM <-> APP01 <-> Active Directory
    """

    if not access_token:
        raise Exception(
            "Missing OrangeHRM OAuth token"
        )

    print(
        "Starting OrangeHRM "
        "employee synchronization..."
    )

    # --------------------------------------------------------
    # Retrieve HR employees
    # --------------------------------------------------------

    payload = get_employees(
        access_token
    )

    orangehrm_employees = (
        payload.get(
            "data",
            [],
        )
    )

    results = {
        "status": "success",
        "employees_processed": 0,
        "employees_created": 0,
        "employees_updated": 0,
        "employees_skipped": 0,
        "ad_identities_found": 0,
        "ad_identities_missing": 0,
        "ad_employee_ids_backfilled": 0,
        "ad_identity_conflicts": 0,
        "supervisors_resolved": 0,
        "supervisors_missing": 0,
        "joiner_requests": 0,
        "mover_requests": 0,
        "leaver_requests": 0,
        "requests_already_pending": 0,
        "employees": [],
    }

    # --------------------------------------------------------
    # Process each HR employee
    # --------------------------------------------------------

    for hr_employee in orangehrm_employees:
        employee_id = str(
            hr_employee.get(
                "employeeId"
            )
            or ""
        ).strip()

        if not employee_id:
            results[
                "employees_skipped"
            ] += 1

            continue

        # ----------------------------------------------------
        # Exclude OrangeHRM administrative identities
        # ----------------------------------------------------

        if (
            employee_id
            in EXCLUDED_HR_EMPLOYEE_IDS
        ):
            results[
                "employees_skipped"
            ] += 1

            create_audit_event(
                db=db,
                employee_id=employee_id,
                event_type="HR_SYNC_EXCLUDED",
                result="SKIPPED",
                details={
                    "reason": (
                        "Employee ID excluded "
                        "from lifecycle automation"
                    )
                },
            )

            continue

        results[
            "employees_processed"
        ] += 1

        emp_number = (
            hr_employee.get(
                "empNumber"
            )
        )

        first_name = (
            hr_employee.get(
                "firstName"
            )
            or ""
        ).strip()

        last_name = (
            hr_employee.get(
                "lastName"
            )
            or ""
        ).strip()

        termination_id = (
            hr_employee.get(
                "terminationId"
            )
        )

        # ----------------------------------------------------
        # Enrichment: job details
        # ----------------------------------------------------

        enrichment = {
            "department": None,
            "job_title": None,
            "employment_status": None,
            "manager": None,
            "manager_employee_id": None,
            "email": None,
        }

        if emp_number is not None:
            try:
                job_payload = (
                    get_employee_job_details(
                        access_token,
                        emp_number,
                    )
                )

                enrichment.update(
                    normalize_job_details(
                        job_payload
                    )
                )

            except Exception as exc:
                create_audit_event(
                    db=db,
                    employee_id=employee_id,
                    event_type=(
                        "HR_JOB_ENRICHMENT_ERROR"
                    ),
                    result="WARNING",
                    details={
                        "empNumber":
                            emp_number,
                        "error":
                            str(exc),
                    },
                )

        # ----------------------------------------------------
        # Enrichment: supervisor
        # ----------------------------------------------------

        if emp_number is not None:
            try:
                supervisor = (
                    resolve_employee_supervisor(
                        access_token=access_token,
                        employee_emp_number=int(
                            emp_number
                        ),
                        employees_response=payload,
                    )
                )

                if supervisor:
                    enrichment["manager"] = (
                        supervisor.get(
                            "name"
                        )
                    )

                    enrichment[
                        "manager_employee_id"
                    ] = str(
                        supervisor.get(
                            "employee_id"
                        )
                    )

                    results[
                        "supervisors_resolved"
                    ] += 1

                else:
                    results[
                        "supervisors_missing"
                    ] += 1

            except Exception as exc:
                results[
                    "supervisors_missing"
                ] += 1

                create_audit_event(
                    db=db,
                    employee_id=employee_id,
                    event_type=(
                        "HR_SUPERVISOR_ENRICHMENT_ERROR"
                    ),
                    result="WARNING",
                    details={
                        "empNumber":
                            emp_number,
                        "error":
                            str(exc),
                    },
                )

        # ----------------------------------------------------
        # Build authoritative IAM representation
        # ----------------------------------------------------

        incoming = {
            "employee_id":
                employee_id,
            "first_name":
                first_name,
            "last_name":
                last_name,
            "email":
                enrichment.get(
                    "email"
                ),
            "department":
                enrichment.get(
                    "department"
                ),
            "job_title":
                enrichment.get(
                    "job_title"
                ),
            "manager":
                enrichment.get(
                    "manager"
                ),
            "manager_employee_id":
                enrichment.get(
                    "manager_employee_id"
                ),
            "employment_status":
                enrichment.get(
                    "employment_status"
                ),
        }

        # ----------------------------------------------------
        # Determine whether this employee is terminated
        # ----------------------------------------------------

        is_terminated = (
            termination_id is not None
        )

        if is_terminated:
            incoming[
                "employment_status"
            ] = "Terminated"

        # ----------------------------------------------------
        # Reconcile against Active Directory
        #
        # Correlation order:
        #   1. employeeID
        #   2. firstname.lastname sAMAccountName fallback
        #
        # If the existing AD account has no employeeID, safely
        # backfill the OrangeHRM employeeId. If the AD account
        # already has a different employeeID, stop and require
        # manual review. Only a true "not found" result may lead
        # to a JOINER request.
        # ----------------------------------------------------

        try:
            correlation = reconcile_ad_identity(
                employee_id=employee_id,
                first_name=first_name,
                last_name=last_name,
            )

            ad_user = correlation.get(
                "ad_user"
            )

            ad_exists = bool(
                correlation.get("exists")
            )

            if correlation.get(
                "employee_id_backfilled"
            ):
                results[
                    "ad_employee_ids_backfilled"
                ] += 1

                create_audit_event(
                    db=db,
                    employee_id=employee_id,
                    event_type="AD_EMPLOYEE_ID_BACKFILLED",
                    result="SUCCESS",
                    details={
                        "sam_account_name":
                            correlation.get(
                                "sam_account_name"
                            ),
                        "correlation_method":
                            correlation.get(
                                "correlation_method"
                            ),
                        "message": (
                            "Existing AD account matched by "
                            "sAMAccountName and employeeID was "
                            "backfilled from OrangeHRM."
                        ),
                    },
                )

        except RuntimeError as exc:
            # Identity conflicts must not become JOINER requests.
            # Example:
            #   HR employeeId = 0002
            #   AD michael.smith employeeID = 1001
            results[
                "ad_identity_conflicts"
            ] += 1

            results[
                "employees_skipped"
            ] += 1

            create_audit_event(
                db=db,
                employee_id=employee_id,
                event_type="AD_IDENTITY_CONFLICT",
                result="BLOCKED",
                details={
                    "expected_sam_account_name":
                        f"{first_name}.{last_name}".lower(),
                    "error": str(exc),
                },
            )

            results["employees"].append({
                "employee_id":
                    employee_id,
                "name":
                    f"{first_name} "
                    f"{last_name}".strip(),
                "lifecycle_event":
                    "IDENTITY_CONFLICT",
                "ad_identity_exists":
                    None,
                "manager":
                    incoming.get("manager"),
                "manager_employee_id":
                    incoming.get(
                        "manager_employee_id"
                    ),
                "error":
                    str(exc),
            })

            continue

        except Exception as exc:
            # A failed AD lookup/write is not the same as "not found".
            # Do not stage a JOINER when AD availability itself is
            # uncertain.
            results[
                "employees_skipped"
            ] += 1

            create_audit_event(
                db=db,
                employee_id=employee_id,
                event_type="AD_CORRELATION_ERROR",
                result="ERROR",
                details={
                    "error": str(exc),
                },
            )

            results["employees"].append({
                "employee_id":
                    employee_id,
                "name":
                    f"{first_name} "
                    f"{last_name}".strip(),
                "lifecycle_event":
                    "CORRELATION_ERROR",
                "manager":
                    incoming.get("manager"),
                "manager_employee_id":
                    incoming.get(
                        "manager_employee_id"
                    ),
                "error":
                    str(exc),
            })

            continue

        if ad_exists:
            results[
                "ad_identities_found"
            ] += 1
        else:
            results[
                "ad_identities_missing"
            ] += 1

        # ----------------------------------------------------
        # Lookup IAM identity
        # ----------------------------------------------------

        existing = (
            db.query(Employee)
            .filter(
                Employee.employee_id
                == employee_id
            )
            .first()
        )

        # ====================================================
        # NEW IAM RECORD
        # ====================================================

        if existing is None:
            new_employee = Employee(
                employee_id=employee_id,
                first_name=first_name,
                last_name=last_name,
                email=incoming.get(
                    "email"
                ),
                department=incoming.get(
                    "department"
                ),
                job_title=incoming.get(
                    "job_title"
                ),
                manager=incoming.get(
                    "manager"
                ),
                employment_status=(
                    incoming.get(
                        "employment_status"
                    )
                    or "Active"
                ),
                source_system=(
                    "OrangeHRM"
                ),
            )

            db.add(
                new_employee
            )

            results[
                "employees_created"
            ] += 1

            # ------------------------------------------------
            # AD already has this employeeID
            #
            # Do NOT create a JOINER. The IAM database is simply
            # learning about an identity that already exists.
            # Reconciliation differences become a MOVER.
            # ------------------------------------------------

            if ad_exists:
                ad_changes = (
                    detect_ad_reconciliation_changes(
                        ad_user=ad_user,
                        incoming=incoming,
                    )
                )

                lifecycle_event = (
                    "NO_CHANGE"
                )

                if (
                    ad_changes
                    and not is_terminated
                ):
                    lifecycle_event = "MOVER"

                    request = (
                        create_identity_request(
                            db=db,
                            employee_id=employee_id,
                            action="MOVER",
                        )
                    )

                    if request:
                        results[
                            "mover_requests"
                        ] += 1

                        create_audit_event(
                            db=db,
                            employee_id=employee_id,
                            request_id=(
                                request.request_id
                            ),
                            event_type=(
                                "AD_RECONCILIATION_MOVER_DETECTED"
                            ),
                            result="PENDING",
                            details={
                                "changes":
                                    ad_changes,
                                "manager":
                                    incoming.get(
                                        "manager"
                                    ),
                                "manager_employee_id":
                                    incoming.get(
                                        "manager_employee_id"
                                    ),
                                "birthright_group":
                                    get_birthright_group(
                                        incoming.get(
                                            "department"
                                        )
                                    ),
                            },
                        )

                    else:
                        results[
                            "requests_already_pending"
                        ] += 1

                elif is_terminated:
                    lifecycle_event = "LEAVER"

                    request = (
                        create_identity_request(
                            db=db,
                            employee_id=employee_id,
                            action="LEAVER",
                        )
                    )

                    if request:
                        results[
                            "leaver_requests"
                        ] += 1

                    else:
                        results[
                            "requests_already_pending"
                        ] += 1

                else:
                    create_audit_event(
                        db=db,
                        employee_id=employee_id,
                        event_type=(
                            "AD_IDENTITY_CORRELATED"
                        ),
                        result="NO_CHANGE",
                        details={
                            "message": (
                                "Employee already exists in AD "
                                "with matching identity data. "
                                "JOINER suppressed."
                            )
                        },
                    )

                results["employees"].append({
                    "employee_id":
                        employee_id,
                    "name":
                        f"{first_name} "
                        f"{last_name}".strip(),
                    "lifecycle_event":
                        lifecycle_event,
                    "ad_identity_exists":
                        True,
                    "department":
                        incoming.get(
                            "department"
                        ),
                    "job_title":
                        incoming.get(
                            "job_title"
                        ),
                    "manager":
                        incoming.get(
                            "manager"
                        ),
                    "manager_employee_id":
                        incoming.get(
                            "manager_employee_id"
                        ),
                    "employment_status":
                        incoming.get(
                            "employment_status"
                        ),
                    "birthright_group":
                        get_birthright_group(
                            incoming.get(
                                "department"
                            )
                        ),
                    "changes":
                        ad_changes,
                })

                continue

            # ------------------------------------------------
            # AD does NOT contain this employeeID
            # ------------------------------------------------

            if not is_terminated:
                request = (
                    create_identity_request(
                        db=db,
                        employee_id=employee_id,
                        action="JOINER",
                    )
                )

                if request:
                    results[
                        "joiner_requests"
                    ] += 1

                    create_audit_event(
                        db=db,
                        employee_id=employee_id,
                        request_id=(
                            request.request_id
                        ),
                        event_type=(
                            "JOINER_DETECTED"
                        ),
                        result="PENDING",
                        details={
                            "first_name":
                                first_name,
                            "last_name":
                                last_name,
                            "department":
                                incoming.get(
                                    "department"
                                ),
                            "job_title":
                                incoming.get(
                                    "job_title"
                                ),
                            "manager":
                                incoming.get(
                                    "manager"
                                ),
                            "manager_employee_id":
                                incoming.get(
                                    "manager_employee_id"
                                ),
                            "birthright_group":
                                get_birthright_group(
                                    incoming.get(
                                        "department"
                                    )
                                ),
                            "ad_identity_exists":
                                False,
                        },
                    )

                else:
                    results[
                        "requests_already_pending"
                    ] += 1

            results["employees"].append({
                "employee_id":
                    employee_id,
                "name":
                    f"{first_name} "
                    f"{last_name}".strip(),
                "lifecycle_event":
                    (
                        "LEAVER"
                        if is_terminated
                        else "JOINER"
                    ),
                "ad_identity_exists":
                    False,
                "department":
                    incoming.get(
                        "department"
                    ),
                "job_title":
                    incoming.get(
                        "job_title"
                    ),
                "manager":
                    incoming.get(
                        "manager"
                    ),
                "manager_employee_id":
                    incoming.get(
                        "manager_employee_id"
                    ),
                "employment_status":
                    incoming.get(
                        "employment_status"
                    ),
                "birthright_group":
                    get_birthright_group(
                        incoming.get(
                            "department"
                        )
                    ),
            })

            continue

        # ====================================================
        # EXISTING IAM RECORD
        # ====================================================

        # ----------------------------------------------------
        # LEAVER
        # ----------------------------------------------------

        if is_terminated:
            already_terminated = (
                existing.employment_status
                == "Terminated"
            )

            previous_status = (
                existing.employment_status
            )

            update_employee_record(
                existing,
                incoming,
            )

            if (
                not already_terminated
                and ad_exists
            ):
                request = (
                    create_identity_request(
                        db=db,
                        employee_id=employee_id,
                        action="LEAVER",
                    )
                )

                if request:
                    results[
                        "leaver_requests"
                    ] += 1

                    create_audit_event(
                        db=db,
                        employee_id=employee_id,
                        request_id=(
                            request.request_id
                        ),
                        event_type=(
                            "LEAVER_DETECTED"
                        ),
                        result="PENDING",
                        details={
                            "terminationId":
                                termination_id,
                            "previous_status":
                                previous_status,
                            "ad_identity_exists":
                                True,
                        },
                    )

                else:
                    results[
                        "requests_already_pending"
                    ] += 1

            results[
                "employees_updated"
            ] += 1

            results["employees"].append({
                "employee_id":
                    employee_id,
                "name":
                    f"{first_name} "
                    f"{last_name}".strip(),
                "lifecycle_event":
                    "LEAVER",
                "ad_identity_exists":
                    ad_exists,
                "manager":
                    incoming.get(
                        "manager"
                    ),
                "manager_employee_id":
                    incoming.get(
                        "manager_employee_id"
                    ),
                "employment_status":
                    "Terminated",
            })

            continue

        # ----------------------------------------------------
        # Existing IAM identity but AD account is missing
        #
        # This is a recoverable JOINER condition. The HR/IAM
        # identity exists, but no AD account exists for the
        # employeeID.
        # ----------------------------------------------------

        if not ad_exists:
            changes = detect_mover_changes(
                existing,
                incoming,
            )

            update_employee_record(
                existing,
                incoming,
            )

            request = (
                create_identity_request(
                    db=db,
                    employee_id=employee_id,
                    action="JOINER",
                )
            )

            if request:
                results[
                    "joiner_requests"
                ] += 1

                create_audit_event(
                    db=db,
                    employee_id=employee_id,
                    request_id=(
                        request.request_id
                    ),
                    event_type=(
                        "JOINER_RECOVERY_DETECTED"
                    ),
                    result="PENDING",
                    details={
                        "reason": (
                            "Employee exists in OrangeHRM "
                            "and APP01 but no Active Directory "
                            "account exists for employeeID."
                        ),
                        "changes":
                            changes,
                        "manager":
                            incoming.get(
                                "manager"
                            ),
                        "manager_employee_id":
                            incoming.get(
                                "manager_employee_id"
                            ),
                        "birthright_group":
                            get_birthright_group(
                                incoming.get(
                                    "department"
                                )
                            ),
                    },
                )

            else:
                results[
                    "requests_already_pending"
                ] += 1

            results[
                "employees_updated"
            ] += 1

            results["employees"].append({
                "employee_id":
                    employee_id,
                "name":
                    f"{first_name} "
                    f"{last_name}".strip(),
                "lifecycle_event":
                    "JOINER",
                "ad_identity_exists":
                    False,
                "department":
                    existing.department,
                "job_title":
                    existing.job_title,
                "manager":
                    existing.manager,
                "manager_employee_id":
                    incoming.get(
                        "manager_employee_id"
                    ),
                "employment_status":
                    existing.employment_status,
                "birthright_group":
                    get_birthright_group(
                        existing.department
                    ),
                "changes":
                    changes,
            })

            continue

        # ====================================================
        # MOVER / NO_CHANGE
        # ====================================================

        iam_changes = detect_mover_changes(
            existing,
            incoming,
        )

        ad_changes = (
            detect_ad_reconciliation_changes(
                ad_user=ad_user,
                incoming=incoming,
            )
        )

        # Combine IAM and AD reconciliation changes. Prefer the
        # AD comparison for fields present in both because the
        # MOVER ultimately needs to reconcile Active Directory.
        changes = dict(
            iam_changes
        )

        changes.update(
            ad_changes
        )

        update_employee_record(
            existing,
            incoming,
        )

        results[
            "employees_updated"
        ] += 1

        lifecycle_event = (
            "NO_CHANGE"
        )

        if changes:
            lifecycle_event = "MOVER"

            request = (
                create_identity_request(
                    db=db,
                    employee_id=employee_id,
                    action="MOVER",
                )
            )

            if request:
                results[
                    "mover_requests"
                ] += 1

                create_audit_event(
                    db=db,
                    employee_id=employee_id,
                    request_id=(
                        request.request_id
                    ),
                    event_type=(
                        "MOVER_DETECTED"
                    ),
                    result="PENDING",
                    details={
                        "changes":
                            changes,
                        "manager":
                            incoming.get(
                                "manager"
                            ),
                        "manager_employee_id":
                            incoming.get(
                                "manager_employee_id"
                            ),
                        "birthright_group":
                            get_birthright_group(
                                incoming.get(
                                    "department"
                                )
                            ),
                        "ad_identity_exists":
                            True,
                    },
                )

            else:
                results[
                    "requests_already_pending"
                ] += 1

        else:
            create_audit_event(
                db=db,
                employee_id=employee_id,
                event_type="HR_SYNC",
                result="NO_CHANGE",
                details={
                    "message": (
                        "Employee synchronized "
                        "with no lifecycle changes."
                    ),
                    "ad_identity_exists":
                        True,
                },
            )

        results["employees"].append({
            "employee_id":
                employee_id,
            "name":
                f"{first_name} "
                f"{last_name}".strip(),
            "lifecycle_event":
                lifecycle_event,
            "ad_identity_exists":
                True,
            "department":
                existing.department,
            "job_title":
                existing.job_title,
            "manager":
                existing.manager,
            "manager_employee_id":
                incoming.get(
                    "manager_employee_id"
                ),
            "employment_status":
                existing.employment_status,
            "birthright_group":
                get_birthright_group(
                    existing.department
                ),
            "changes":
                changes,
        })

    # ========================================================
    # Commit reconciliation transaction
    # ========================================================

    try:
        db.commit()

    except Exception:
        db.rollback()
        raise

    return results
