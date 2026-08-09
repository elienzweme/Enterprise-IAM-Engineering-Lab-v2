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

    token_url = (
        f"{BASE_URL}/oauth2/token"
    )


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
        timeout=30
    )


    print("TOKEN RESPONSE STATUS:")
    print(response.status_code)

    print("TOKEN RESPONSE BODY:")
    print(response.text)


    response.raise_for_status()

    return response.json()



def get_employees(access_token: str) -> dict:
    """
    Retrieve OrangeHRM employees.
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
        timeout=30
    )


    response.raise_for_status()

    return response.json()



def get_employee_job_details(
    access_token: str,
    emp_number: int
) -> dict:
    """
    Retrieve job details for employee.
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
        timeout=30
    )


    response.raise_for_status()

    return response.json()