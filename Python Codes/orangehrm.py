import os

import httpx
from dotenv import load_dotenv


load_dotenv()


BASE_URL = os.getenv("ORANGEHRM_BASE_URL")
CLIENT_ID = os.getenv("ORANGEHRM_CLIENT_ID")
CLIENT_SECRET = os.getenv("ORANGEHRM_CLIENT_SECRET")
REDIRECT_URI = os.getenv("ORANGEHRM_REDIRECT_URI")


def build_authorization_url(state: str) -> str:
    """
    Build the OrangeHRM OAuth2 authorization URL.
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
    Exchange an OAuth authorization code for an access token.
    """

    token_url = f"{BASE_URL}/oauth2/token"

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    response = httpx.post(
        token_url,
        data=data,
        timeout=30.0,
    )

    response.raise_for_status()

    return response.json()


def get_employees(access_token: str) -> dict:
    """
    Retrieve the OrangeHRM employee list.
    """

    employee_url = (
        f"{BASE_URL}/index.php/api/v2/pim/employees"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    response = httpx.get(
        employee_url,
        headers=headers,
        timeout=30.0,
    )

    response.raise_for_status()

    return response.json()


def get_employee_job_details(
    access_token: str,
    emp_number: int,
) -> dict:
    """
    Retrieve job details for one OrangeHRM employee.

    OrangeHRM uses empNumber for this API, which is different
    from the employeeId field used by the IAM database.
    """

    job_details_url = (
        f"{BASE_URL}/index.php/api/v2/pim/employees/"
        f"{emp_number}/job-details"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    response = httpx.get(
        job_details_url,
        headers=headers,
        timeout=30.0,
    )

    response.raise_for_status()

    return response.json()