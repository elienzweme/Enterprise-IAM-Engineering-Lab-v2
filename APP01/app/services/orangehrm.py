import os

import httpx
from dotenv import load_dotenv


load_dotenv()


BASE_URL = os.getenv("ORANGEHRM_BASE_URL")
CLIENT_ID = os.getenv("ORANGEHRM_CLIENT_ID")
CLIENT_SECRET = os.getenv("ORANGEHRM_CLIENT_SECRET")
REDIRECT_URI = os.getenv("ORANGEHRM_REDIRECT_URI")


# ============================================================
# OAuth2
# ============================================================

def build_authorization_url(state: str) -> str:
    """
    Build OrangeHRM OAuth2 authorization URL.
    """

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    query = str(httpx.QueryParams(params))

    return f"{BASE_URL}/oauth2/authorize?{query}"


def exchange_authorization_code(code: str) -> dict:
    """
    Exchange OAuth authorization code
    for an OrangeHRM access token.
    """

    token_url = f"{BASE_URL}/oauth2/token"

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    response = httpx.post(
        token_url,
        data=data,
        headers=headers,
        timeout=30,
    )

    print("TOKEN RESPONSE STATUS:")
    print(response.status_code)

    print("TOKEN RESPONSE BODY:")

    response.raise_for_status()

    return response.json()


# ============================================================
# Employee API
# ============================================================

def get_employees(access_token: str) -> dict:
    """
    Retrieve OrangeHRM employees.

    Endpoint:
        GET /api/v2/pim/employees
    """

    employee_url = f"{BASE_URL}/api/v2/pim/employees"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    response = httpx.get(
        employee_url,
        headers=headers,
        params={
            "limit": 100,
            "offset": 0,
            "model": "detailed",
            "includeEmployees": "currentAndPast",
        },
        timeout=30,
    )

    print("EMPLOYEE API URL:")
    print(employee_url)

    print("EMPLOYEE API STATUS:")
    print(response.status_code)

    print("EMPLOYEE API RESPONSE:")

    response.raise_for_status()

    return response.json()


# ============================================================
# Employee Job Details - READ
# ============================================================

def get_employee_job_details(
    access_token: str,
    emp_number: int,
) -> dict:
    """
    Retrieve job details for an OrangeHRM employee.

    Endpoint:
        GET /api/v2/pim/employees/{empNumber}/job-details
    """

    job_details_url = (
        f"{BASE_URL}/api/v2/pim/employees/"
        f"{emp_number}/job-details"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    response = httpx.get(
        job_details_url,
        headers=headers,
        timeout=30,
    )

    print("JOB DETAILS URL:")
    print(job_details_url)

    print("JOB DETAILS STATUS:")
    print(response.status_code)

    print("JOB DETAILS RESPONSE:")

    response.raise_for_status()

    return response.json()


# ============================================================
# Employee Job Details - UPDATE
# ============================================================

def update_employee_job_details(
    access_token: str,
    emp_number: int,
    joined_date: str | None = None,
    job_title_id: int | None = None,
    emp_status_id: int | None = None,
    job_category_id: int | None = None,
    subunit_id: int | None = None,
    location_id: int | None = None,
) -> dict:
    """
    Update OrangeHRM job details for an employee.

    Endpoint:
        PUT /api/v2/pim/employees/{empNumber}/job-details

    Supported fields:
        joinedDate
        jobTitleId
        empStatusId
        jobCategoryId
        subunitId
        locationId
    """

    url = (
        f"{BASE_URL}/api/v2/pim/employees/"
        f"{emp_number}/job-details"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    payload = {}

    if joined_date is not None:
        payload["joinedDate"] = joined_date

    if job_title_id is not None:
        payload["jobTitleId"] = int(job_title_id)

    if emp_status_id is not None:
        payload["empStatusId"] = int(emp_status_id)

    if job_category_id is not None:
        payload["jobCategoryId"] = int(job_category_id)

    if subunit_id is not None:
        payload["subunitId"] = int(subunit_id)

    if location_id is not None:
        payload["locationId"] = int(location_id)

    if not payload:
        raise ValueError(
            "No OrangeHRM job-detail fields were supplied."
        )

    print("UPDATE JOB DETAILS URL:")
    print(url)

    print("UPDATE JOB DETAILS PAYLOAD:")
    print(payload)

    response = httpx.put(
        url,
        headers=headers,
        json=payload,
        timeout=30,
    )

    print("UPDATE JOB DETAILS STATUS:")
    print(response.status_code)

    print("UPDATE JOB DETAILS RESPONSE:")

    response.raise_for_status()

    return response.json()


# ============================================================
# Employee Supervisors - READ
# ============================================================

def get_employee_supervisors(
    access_token: str,
    emp_number: int,
) -> dict:
    """
    Retrieve supervisors assigned to an OrangeHRM employee.

    Endpoint:
        GET /api/v2/pim/employees/{empNumber}/supervisors
    """

    url = (
        f"{BASE_URL}/api/v2/pim/employees/"
        f"{emp_number}/supervisors"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    response = httpx.get(
        url,
        headers=headers,
        timeout=30,
    )

    print("SUPERVISOR API URL:")
    print(url)

    print("SUPERVISOR API STATUS:")
    print(response.status_code)

    print("SUPERVISOR API RESPONSE:")

    response.raise_for_status()

    return response.json()


# ============================================================
# Employee Supervisors - CREATE
# ============================================================

def add_employee_supervisor(
    access_token: str,
    employee_emp_number: int,
    supervisor_emp_number: int,
    reporting_method_id: int = 1,
) -> dict:
    """
    Assign a supervisor to an OrangeHRM employee.

    Endpoint:
        POST /api/v2/pim/employees/{empNumber}/supervisors

    Important:
        employee_emp_number
            = employee receiving the supervisor

        supervisor_emp_number
            = OrangeHRM internal empNumber of the supervisor

        reporting_method_id
            = OrangeHRM reporting method ID
    """

    if employee_emp_number == supervisor_emp_number:
        raise ValueError(
            "An employee cannot be assigned as their own supervisor."
        )

    url = (
        f"{BASE_URL}/api/v2/pim/employees/"
        f"{employee_emp_number}/supervisors"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    payload = {
        "empNumber": int(supervisor_emp_number),
        "reportingMethodId": int(reporting_method_id),
    }

    print("ADD SUPERVISOR URL:")
    print(url)

    print("ADD SUPERVISOR PAYLOAD:")
    print(payload)

    response = httpx.post(
        url,
        headers=headers,
        json=payload,
        timeout=30,
    )

    print("ADD SUPERVISOR STATUS:")
    print(response.status_code)

    print("ADD SUPERVISOR RESPONSE:")

    response.raise_for_status()

    return response.json()


# ============================================================
# Employee Supervisors - IDEMPOTENT ASSIGNMENT
# ============================================================

def ensure_employee_supervisor(
    access_token: str,
    employee_emp_number: int,
    supervisor_emp_number: int,
    reporting_method_id: int = 1,
) -> dict:
    """
    Ensure that an OrangeHRM employee has the requested supervisor.

    This function is intended for repeated IAM synchronization runs.

    If the relationship already exists:
        no change is made.

    If the relationship does not exist:
        it is created.
    """

    if employee_emp_number == supervisor_emp_number:
        raise ValueError(
            "An employee cannot be assigned as their own supervisor."
        )

    current = get_employee_supervisors(
        access_token=access_token,
        emp_number=employee_emp_number,
    )

    supervisors = current.get("data", [])

    for supervisor in supervisors:

        existing_emp_number = supervisor.get("empNumber")

        # Some OrangeHRM responses may nest the employee
        # information under "supervisor".
        if existing_emp_number is None:
            supervisor_data = supervisor.get("supervisor")

            if isinstance(supervisor_data, dict):
                existing_emp_number = supervisor_data.get(
                    "empNumber"
                )

        if str(existing_emp_number) == str(
            supervisor_emp_number
        ):
            return {
                "success": True,
                "changed": False,
                "employee_emp_number": employee_emp_number,
                "supervisor_emp_number": supervisor_emp_number,
                "message": "Supervisor already assigned.",
            }

    result = add_employee_supervisor(
        access_token=access_token,
        employee_emp_number=employee_emp_number,
        supervisor_emp_number=supervisor_emp_number,
        reporting_method_id=reporting_method_id,
    )

    return {
        "success": True,
        "changed": True,
        "employee_emp_number": employee_emp_number,
        "supervisor_emp_number": supervisor_emp_number,
        "message": "Supervisor assigned successfully.",
        "result": result,
    }

# ============================================================
# Employee Correlation Helpers
# ============================================================

def find_employee_by_emp_number(
    employees_response: dict,
    emp_number: int,
) -> dict | None:
    """Find an OrangeHRM employee by internal empNumber."""
    for employee in employees_response.get("data", []):
        if str(employee.get("empNumber")) == str(emp_number):
            return employee
    return None


def resolve_employee_supervisor(
    access_token: str,
    employee_emp_number: int,
    employees_response: dict | None = None,
) -> dict | None:
    """Resolve an employee's immediate supervisor to the HR employeeId."""
    response = get_employee_supervisors(
        access_token=access_token,
        emp_number=employee_emp_number,
    )
    supervisors = response.get("data", [])
    if not supervisors:
        return None

    supervisor = supervisors[0]
    supervisor_emp_number = supervisor.get("empNumber")
    if supervisor_emp_number is None and isinstance(supervisor.get("supervisor"), dict):
        supervisor = supervisor["supervisor"]
        supervisor_emp_number = supervisor.get("empNumber")
    if supervisor_emp_number is None:
        return None

    first_name = supervisor.get("firstName")
    middle_name = supervisor.get("middleName")
    last_name = supervisor.get("lastName")
    supervisor_employee_id = supervisor.get("employeeId")

    if not supervisor_employee_id and employees_response is not None:
        full_employee = find_employee_by_emp_number(
            employees_response, supervisor_emp_number
        )
        if full_employee:
            supervisor_employee_id = full_employee.get("employeeId")
            first_name = first_name or full_employee.get("firstName")
            middle_name = middle_name or full_employee.get("middleName")
            last_name = last_name or full_employee.get("lastName")

    if not supervisor_employee_id:
        raise RuntimeError(
            f"Supervisor empNumber {supervisor_emp_number} could not be correlated "
            "to an OrangeHRM employeeId."
        )

    name = " ".join(str(x).strip() for x in [first_name, middle_name, last_name] if x)
    return {
        "emp_number": int(supervisor_emp_number),
        "employee_id": str(supervisor_employee_id),
        "first_name": first_name,
        "middle_name": middle_name,
        "last_name": last_name,
        "name": name or None,
    }
