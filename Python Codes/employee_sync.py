from sqlalchemy.orm import Session

from app.models.models import Employee, AuditEvent

from app.services.orangehrm import (
    get_employees,
    get_employee_job_details,
)

from app.config.identity_scope import (
    DEPARTMENT_GROUP_MAPPING
)

from app.services.hr_sync_scope import (
    is_hr_managed_user
)


def get_birthright_group(department):
    """
    Returns department RBAC group.

    Birthright groups only.
    Privileged groups are intentionally excluded.
    """

    if not department:
        return None

    return DEPARTMENT_GROUP_MAPPING.get(
        department
    )


def build_identity_record(
        first_name,
        last_name,
        department,
        job_title,
        employee_id
):
    """
    Creates IAM identity candidate.
    """

    return {
        "employee_id": employee_id,
        "first_name": first_name,
        "last_name": last_name,
        "department": department,
        "job_title": job_title
    }



def sync_orangehrm_employees(
        access_token: str,
        db: Session
):

    """
    OrangeHRM -> IAM Employee Synchronization

    Source of Truth:
        OrangeHRM

    Scope:
        HR Managed identities only


    Excluded:
        Contractors
        Service Accounts
        Privileged Accounts
        Test Accounts


    Flow:

    OrangeHRM
        |
        v
    Identity Scope Validation
        |
        v
    IAM Database
        |
        v
    AD Joiner Automation
    """


    payload = get_employees(
        access_token
    )


    employees = payload.get(
        "data",
        []
    )


    created = 0
    updated = 0
    unchanged = 0
    skipped = 0
    errors = 0



    for hr_employee in employees:


        try:


            employee_id = str(
                hr_employee.get(
                    "employeeId"
                )
                or ""
            ).strip()



            if not employee_id:

                skipped += 1
                continue



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



            emp_number = hr_employee.get(
                "empNumber"
            )



            department = None
            job_title = None
            employment_status = "Active"



            #
            # Retrieve OrangeHRM job data
            #

            if emp_number:


                job_payload = (
                    get_employee_job_details(
                        access_token,
                        int(emp_number)
                    )
                )


                job_data = (
                    job_payload
                    .get(
                        "data",
                        {}
                    )
                )


                department = (
                    job_data
                    .get(
                        "subunit",
                        {}
                    )
                    .get(
                        "name"
                    )
                )


                job_title = (
                    job_data
                    .get(
                        "jobTitle",
                        {}
                    )
                    .get(
                        "title"
                    )
                )



                status = (
                    job_data
                    .get(
                        "empStatus",
                        {}
                    )
                    .get(
                        "name"
                    )
                )


                if status:

                    employment_status = status



            #
            # HR Identity Scope Validation
            #

            identity = {

                "sAMAccountName":
                    employee_id,

                "department":
                    department

            }



            if not is_hr_managed_user(identity):


                db.add(

                    AuditEvent(

                        employee_id=employee_id,

                        event_type=
                        "Identity Excluded",

                        system=
                        "IAM Scope Engine",

                        result=
                        "Skipped",

                        details=
                        (
                            "Identity outside HR "
                            "managed scope"
                        )

                    )

                )


                skipped += 1

                continue




            #
            # Birthright RBAC
            #

            birthright_group = (
                get_birthright_group(
                    department
                )
            )



            #
            # Database lookup
            #

            employee = (

                db.query(Employee)

                .filter(

                    Employee.employee_id
                    ==
                    employee_id

                )

                .first()

            )




            #
            # CREATE
            #

            if employee is None:



                employee = Employee(

                    employee_id=
                    employee_id,

                    first_name=
                    first_name,

                    last_name=
                    last_name,

                    department=
                    department,

                    job_title=
                    job_title,

                    employment_status=
                    employment_status,

                    source_system=
                    "OrangeHRM"

                )


                db.add(
                    employee
                )


                db.add(

                    AuditEvent(

                        employee_id=
                        employee_id,

                        event_type=
                        "Joiner Candidate",

                        system=
                        "IAM",

                        result=
                        "Created",

                        details=
                        (
                            f"Department: {department}; "
                            f"Birthright Group: "
                            f"{birthright_group}"
                        )

                    )

                )


                created += 1



            #
            # UPDATE
            #

            else:


                changed = False

                fields = []



                updates = {


                    "first_name":
                    first_name,


                    "last_name":
                    last_name,


                    "department":
                    department,


                    "job_title":
                    job_title,


                    "employment_status":
                    employment_status


                }



                for field,value in updates.items():


                    if value and getattr(
                        employee,
                        field
                    ) != value:


                        setattr(
                            employee,
                            field,
                            value
                        )


                        changed = True

                        fields.append(
                            field
                        )




                if changed:


                    db.add(

                        AuditEvent(

                            employee_id=
                            employee_id,

                            event_type=
                            "Employee Sync",

                            system=
                            "OrangeHRM",

                            result=
                            "Updated",

                            details=
                            (
                                "Changed fields: "
                                +
                                ", ".join(fields)
                            )

                        )

                    )


                    updated += 1



                else:


                    unchanged += 1




        except Exception as e:


            errors += 1


            db.add(

                AuditEvent(

                    employee_id=
                    employee_id,

                    event_type=
                    "Sync Error",

                    system=
                    "OrangeHRM",

                    result=
                    "Failed",

                    details=
                    str(e)

                )

            )




    db.commit()



    return {


        "status":
        "completed",


        "source":
        "OrangeHRM",


        "received":
        len(employees),


        "created":
        created,


        "updated":
        updated,


        "unchanged":
        unchanged,


        "skipped":
        skipped,


        "errors":
        errors

    }