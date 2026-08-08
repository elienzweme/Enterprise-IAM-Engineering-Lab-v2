from sqlalchemy.orm import Session

from app.models.models import Employee, AuditEvent
from app.services.orangehrm import (
    get_employees,
    get_employee_job_details,
)


def sync_orangehrm_employees(
    access_token: str,
    db: Session,
) -> dict:
    """
    Synchronize OrangeHRM employees and job details into PostgreSQL.

    Matching:
        OrangeHRM employeeId -> PostgreSQL Employee.employee_id

    Existing employees are updated.
    New employees are created.
    Re-running the sync will not create duplicates.
    """

    payload = get_employees(access_token)
    employees = payload.get("data", [])

    created = 0
    updated = 0
    unchanged = 0
    skipped = 0
    job_detail_errors = 0

    for hr_employee in employees:

        employee_id = str(
            hr_employee.get("employeeId") or ""
        ).strip()

        if not employee_id:
            skipped += 1
            continue

        first_name = (
            hr_employee.get("firstName") or ""
        ).strip()

        last_name = (
            hr_employee.get("lastName") or ""
        ).strip()

        # OrangeHRM internal employee identifier
        emp_number = hr_employee.get("empNumber")

        job_title = None
        department = None
        employment_status = None
        termination_date = None

        # ---------------------------------------------------------
        # Retrieve job details from OrangeHRM
        # ---------------------------------------------------------

        if emp_number is not None:

            try:

                job_payload = get_employee_job_details(
                    access_token,
                    int(emp_number),
                )

                job_data = job_payload.get("data", {})

                job_title_data = (
                    job_data.get("jobTitle") or {}
                )

                emp_status_data = (
                    job_data.get("empStatus") or {}
                )

                subunit_data = (
                    job_data.get("subunit") or {}
                )

                termination_data = (
                    job_data.get(
                        "employeeTerminationRecord"
                    )
                    or {}
                )

                job_title = (
                    job_title_data.get("title") or ""
                ).strip() or None

                department = (
                    subunit_data.get("name") or ""
                ).strip() or None

                employment_status = (
                    emp_status_data.get("name") or ""
                ).strip() or None

                termination_date = (
                    termination_data.get("date")
                )

                # If OrangeHRM contains a termination date,
                # explicitly mark the employee terminated.
                if termination_date:
                    employment_status = "Terminated"

            except Exception:

                # One employee failing job-detail retrieval
                # should not stop the entire workforce sync.
                job_detail_errors += 1

        # ---------------------------------------------------------
        # Fallback employment status
        # ---------------------------------------------------------

        if not employment_status:

            termination_id = hr_employee.get(
                "terminationId"
            )

            employment_status = (
                "Terminated"
                if termination_id is not None
                else "Active"
            )

        # ---------------------------------------------------------
        # Look for existing PostgreSQL employee
        # ---------------------------------------------------------

        employee = (
            db.query(Employee)
            .filter(
                Employee.employee_id == employee_id
            )
            .first()
        )

        # =========================================================
        # CREATE NEW EMPLOYEE
        # =========================================================

        if employee is None:

            employee = Employee(
                employee_id=employee_id,
                first_name=first_name,
                last_name=last_name,
                department=department,
                job_title=job_title,
                employment_status=employment_status,
                source_system="OrangeHRM",
            )

            db.add(employee)

            db.add(
                AuditEvent(
                    employee_id=employee_id,
                    event_type="Employee Sync",
                    system="OrangeHRM",
                    result="Created",
                    details=(
                        "Employee imported from OrangeHRM "
                        "into IAM platform with available "
                        "job details."
                    ),
                )
            )

            created += 1

        # =========================================================
        # UPDATE EXISTING EMPLOYEE
        # =========================================================

        else:

            changed = False
            changed_fields = []

            if employee.first_name != first_name:

                employee.first_name = first_name
                changed = True
                changed_fields.append(
                    "first_name"
                )

            if employee.last_name != last_name:

                employee.last_name = last_name
                changed = True
                changed_fields.append(
                    "last_name"
                )

            # Do not overwrite valid PostgreSQL values with
            # None if the OrangeHRM job-details request fails.

            if (
                department is not None
                and employee.department != department
            ):

                employee.department = department
                changed = True
                changed_fields.append(
                    "department"
                )

            if (
                job_title is not None
                and employee.job_title != job_title
            ):

                employee.job_title = job_title
                changed = True
                changed_fields.append(
                    "job_title"
                )

            if (
                employment_status is not None
                and employee.employment_status
                != employment_status
            ):

                employee.employment_status = (
                    employment_status
                )

                changed = True
                changed_fields.append(
                    "employment_status"
                )

            if (
                employee.source_system
                != "OrangeHRM"
            ):

                employee.source_system = "OrangeHRM"
                changed = True
                changed_fields.append(
                    "source_system"
                )

            # -----------------------------------------------------
            # Audit changes
            # -----------------------------------------------------

            if changed:

                db.add(
                    AuditEvent(
                        employee_id=employee_id,
                        event_type="Employee Sync",
                        system="OrangeHRM",
                        result="Updated",
                        details=(
                            "Employee record updated "
                            "from OrangeHRM. "
                            "Changed fields: "
                            + ", ".join(
                                changed_fields
                            )
                            + "."
                        ),
                    )
                )

                updated += 1

            else:

                unchanged += 1

    # -------------------------------------------------------------
    # Commit synchronization
    # -------------------------------------------------------------

    db.commit()

    return {
        "status": "completed",
        "source": "OrangeHRM",
        "employees_received": len(employees),
        "created": created,
        "updated": updated,
        "unchanged": unchanged,
        "skipped": skipped,
        "job_detail_errors": job_detail_errors,
    }