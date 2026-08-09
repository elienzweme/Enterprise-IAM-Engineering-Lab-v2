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


# ============================================================
# ORANGEHRM JOB DATA NORMALIZATION
# ============================================================


def normalize_job_details(
    payload: dict,
) -> dict:
    """
    Convert OrangeHRM job-details JSON into IAM attributes.

    The helper is intentionally tolerant of slightly different
    OrangeHRM response structures.
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
    # Manager / Supervisor
    # --------------------------------------------------------

    manager = None

    supervisor_raw = _first_present(
        data,
        "supervisor",
        "manager",
    )

    if isinstance(
        supervisor_raw,
        str,
    ):

        manager = (
            supervisor_raw.strip()
            or None
        )

    elif isinstance(
        supervisor_raw,
        dict,
    ):

        manager = _extract_name(
            supervisor_raw
        )

        if not manager:

            first_name = (
                supervisor_raw.get(
                    "firstName"
                )
                or ""
            )

            last_name = (
                supervisor_raw.get(
                    "lastName"
                )
                or ""
            )

            full_name = (
                f"{first_name} {last_name}"
                .strip()
            )

            manager = (
                full_name
                or None
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
        "manager": manager,
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
    3. Detect Joiner/Mover/Leaver lifecycle conditions.
    4. Update the IAM employee record.
    5. Stage IdentityRequest records.
    6. Write AuditEvent records.

    IMPORTANT:

    This function DOES NOT provision Active Directory.

    AD changes happen only after the staged IdentityRequest
    is processed by the provisioning workflow.
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
        # Enrichment
        # ----------------------------------------------------

        enrichment = {}

        if emp_number is not None:

            try:

                job_payload = (
                    get_employee_job_details(
                        access_token,
                        emp_number,
                    )
                )

                enrichment = (
                    normalize_job_details(
                        job_payload
                    )
                )

            except Exception as exc:

                enrichment = {
                    "department": None,
                    "job_title": None,
                    "employment_status": None,
                    "manager": None,
                    "email": None,
                }

                create_audit_event(
                    db=db,
                    employee_id=employee_id,
                    event_type=(
                        "HR_ENRICHMENT_ERROR"
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
        # JOINER
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

            # A terminated identity should not
            # generate a new Joiner.

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
                "department":
                    incoming.get(
                        "department"
                    ),
                "job_title":
                    incoming.get(
                        "job_title"
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
        # LEAVER
        # ====================================================

        if is_terminated:

            already_terminated = (
                existing.employment_status
                == "Terminated"
            )

            update_employee_record(
                existing,
                incoming,
            )

            if not already_terminated:

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
                                (
                                    existing
                                    .employment_status
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
                    "LEAVER",
                "employment_status":
                    "Terminated",
            })

            continue

        # ====================================================
        # MOVER DETECTION
        # ====================================================

        changes = detect_mover_changes(
            existing,
            incoming,
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

        # ----------------------------------------------------
        # Stage mover
        # ----------------------------------------------------

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
            "department":
                existing.department,
            "job_title":
                existing.job_title,
            "manager":
                existing.manager,
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