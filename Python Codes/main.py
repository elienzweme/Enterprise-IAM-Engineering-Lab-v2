import secrets

import httpx
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
)
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.api.employees import (
    router as employees_router,
)
from app.database import get_db
from app.services.employee_sync import (
    sync_orangehrm_employees,
)
from app.services.orangehrm import (
    build_authorization_url,
    exchange_authorization_code,
    get_employee_job_details,
    get_employees,
)


app = FastAPI(
    title="Enterprise IAM Platform",
    description=(
        "Identity lifecycle orchestration "
        "and access management platform"
    ),
    version="2.0.0",
)


app.include_router(employees_router)


oauth_state = None


orangehrm_token = {
    "access_token": None,
    "token_type": None,
    "expires_in": None,
}


@app.get("/")
def home():
    return {
        "application": "Enterprise IAM Platform",
        "server": "APP01",
        "status": "online",
        "version": "2.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "server": "APP01",
    }


@app.get("/oauth/login")
def orangehrm_login():
    """
    Start the OrangeHRM OAuth2 authorization flow.
    """

    global oauth_state

    oauth_state = secrets.token_urlsafe(32)

    authorization_url = build_authorization_url(
        oauth_state
    )

    return RedirectResponse(
        authorization_url
    )


@app.get("/oauth/callback")
def orangehrm_callback(
    code: str,
    state: str,
):
    """
    Receive the OrangeHRM authorization code
    and exchange it for an OAuth access token.
    """

    if state != oauth_state:
        raise HTTPException(
            status_code=400,
            detail="Invalid OAuth state",
        )

    try:

        token_response = (
            exchange_authorization_code(code)
        )

    except httpx.HTTPStatusError as exc:

        raise HTTPException(
            status_code=502,
            detail=exc.response.text,
        )

    orangehrm_token["access_token"] = (
        token_response.get("access_token")
    )

    orangehrm_token["token_type"] = (
        token_response.get("token_type")
    )

    orangehrm_token["expires_in"] = (
        token_response.get("expires_in")
    )

    return {
        "status": "OrangeHRM OAuth successful",
        "token_type": (
            orangehrm_token["token_type"]
        ),
        "expires_in": (
            orangehrm_token["expires_in"]
        ),
        "access_token_received": bool(
            orangehrm_token["access_token"]
        ),
    }


@app.get("/integrations/orangehrm/status")
def orangehrm_status():
    """
    Show the current OrangeHRM integration status
    without exposing the access token.
    """

    return {
        "integration": "OrangeHRM",
        "authenticated": bool(
            orangehrm_token["access_token"]
        ),
        "token_type": (
            orangehrm_token["token_type"]
        ),
        "expires_in": (
            orangehrm_token["expires_in"]
        ),
    }


@app.get("/integrations/orangehrm/employees")
def orangehrm_employees():
    """
    Retrieve basic employee records directly
    from OrangeHRM.
    """

    access_token = (
        orangehrm_token["access_token"]
    )

    if not access_token:

        raise HTTPException(
            status_code=401,
            detail=(
                "OrangeHRM is not authenticated. "
                "Open /oauth/login first."
            ),
        )

    try:

        return get_employees(
            access_token
        )

    except httpx.HTTPStatusError as exc:

        raise HTTPException(
            status_code=502,
            detail=exc.response.text,
        )


@app.get(
    "/integrations/orangehrm/employees/"
    "{emp_number}/job-details"
)
def orangehrm_employee_job_details(
    emp_number: int,
):
    """
    Retrieve job details for a specific OrangeHRM
    employee using the OrangeHRM empNumber.
    """

    access_token = (
        orangehrm_token["access_token"]
    )

    if not access_token:

        raise HTTPException(
            status_code=401,
            detail=(
                "OrangeHRM is not authenticated. "
                "Open /oauth/login first."
            ),
        )

    try:

        return get_employee_job_details(
            access_token,
            emp_number,
        )

    except httpx.HTTPStatusError as exc:

        raise HTTPException(
            status_code=502,
            detail=exc.response.text,
        )


@app.post("/integrations/orangehrm/sync")
def orangehrm_sync(
    db: Session = Depends(get_db),
):
    """
    Synchronize OrangeHRM employees into
    the IAM PostgreSQL database.
    """

    access_token = (
        orangehrm_token["access_token"]
    )

    if not access_token:

        raise HTTPException(
            status_code=401,
            detail=(
                "OrangeHRM is not authenticated. "
                "Open /oauth/login first."
            ),
        )

    try:

        return sync_orangehrm_employees(
            access_token,
            db,
        )

    except httpx.HTTPStatusError as exc:

        raise HTTPException(
            status_code=502,
            detail=exc.response.text,
        )