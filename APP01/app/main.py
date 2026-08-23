# app/main.py

import secrets

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse

from app.database import SessionLocal

from app.api.identity_requests import (
    router as identity_requests_router,
)

from app.services.orangehrm import (
    build_authorization_url,
    exchange_authorization_code,
    get_employees,
    get_employee_job_details,
    get_employee_supervisors,
    resolve_employee_supervisor,
)

from app.services.employee_sync import (
    sync_orangehrm_employees,
)


# ============================================================
# FastAPI Application
# ============================================================

app = FastAPI(
    title="Enterprise IAM Platform",
    description=(
        "Enterprise Identity and Access Management platform "
        "integrating OrangeHRM with IAM lifecycle automation."
    ),
    version="1.0.0",
)


# ============================================================
# API Routers
# ============================================================

app.include_router(
    identity_requests_router
)


# ============================================================
# TEMPORARY OAUTH STORAGE
# ============================================================
#
# LAB VERSION:
# OAuth state and access token are stored in the Uvicorn
# process memory.
#
# IMPORTANT:
# Restarting/reloading Uvicorn will clear these values.
#
# FUTURE / PRODUCTION:
# Replace this with persistent database or Redis storage.
#
# ============================================================

oauth_state: str | None = None
oauth_token: str | None = None


# ============================================================
# Root / Health Check
# ============================================================

@app.get("/")
def root():
    """
    Basic health check for the IAM platform.
    """

    return {
        "application": "Enterprise IAM Platform",
        "version": "1.0.0",
        "status": "running",
    }


# ============================================================
# OrangeHRM OAuth Login
# ============================================================

@app.get("/oauth/login")
def oauth_login():
    """
    Start the OrangeHRM OAuth2 Authorization Code flow.
    """

    global oauth_state

    oauth_state = secrets.token_urlsafe(32)

    authorization_url = build_authorization_url(
        oauth_state
    )

    return RedirectResponse(
        url=authorization_url
    )


# ============================================================
# OrangeHRM OAuth Callback
# ============================================================

@app.get("/oauth/callback")
def oauth_callback(
    code: str,
    state: str | None = None,
):
    """
    Receive the authorization code from OrangeHRM
    and exchange it for an OAuth access token.
    """

    global oauth_state
    global oauth_token

    # --------------------------------------------------------
    # Validate OAuth state
    # --------------------------------------------------------

    if not state or not oauth_state or state != oauth_state:

        raise HTTPException(
            status_code=400,
            detail="Invalid OAuth state",
        )

    try:

        # ----------------------------------------------------
        # Exchange authorization code for token
        # ----------------------------------------------------

        token_response = exchange_authorization_code(
            code
        )

        # ----------------------------------------------------
        # Extract access token
        # ----------------------------------------------------

        access_token = token_response.get(
            "access_token"
        )

        if not access_token:

            raise HTTPException(
                status_code=500,
                detail=(
                    "OrangeHRM token response did not "
                    "contain an access_token."
                ),
            )

        # ----------------------------------------------------
        # Store token in FastAPI/Uvicorn process memory
        # ----------------------------------------------------

        oauth_token = access_token

        oauth_state = None

        # ----------------------------------------------------
        # Return safe response
        # ----------------------------------------------------

        return {
            "message": (
                "OAuth authentication completed successfully"
            ),
            "token_received": True,
            "token_type": token_response.get(
                "token_type"
            ),
            "expires_in": token_response.get(
                "expires_in"
            ),
        }

    except HTTPException:
        raise

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# ============================================================
# OAuth Status
# ============================================================

@app.get("/oauth/status")
def oauth_status():
    """
    Check whether this FastAPI process currently
    has an OrangeHRM OAuth access token.
    """

    return {
        "token_available":
            oauth_token is not None
    }


# ============================================================
# OrangeHRM Employee API Test
# ============================================================

@app.get("/employees")
def employees():
    """
    Retrieve employees directly from OrangeHRM.

    This endpoint verifies:

        FastAPI
            ->
        OAuth Token
            ->
        OrangeHRM API
    """

    global oauth_token

    if not oauth_token:

        raise HTTPException(
            status_code=401,
            detail=(
                "No OAuth token available. "
                "Authenticate through /oauth/login first."
            ),
        )

    try:

        result = get_employees(
            oauth_token
        )

        return result

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# ============================================================
# OrangeHRM Employee Job Details API Test
# ============================================================

@app.get("/employees/{emp_number}/job-details")
def employee_job_details(emp_number: int):
    """
    Retrieve job details for a specific OrangeHRM employee.
    """

    global oauth_token

    if not oauth_token:
        raise HTTPException(
            status_code=401,
            detail="OrangeHRM OAuth token is not available.",
        )

    try:
        return get_employee_job_details(
            access_token=oauth_token,
            emp_number=emp_number,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# ============================================================
# OrangeHRM Employee Supervisor API Test
# ============================================================

@app.get("/employees/{emp_number}/supervisors")
def employee_supervisors(emp_number: int):
    """
    Retrieve supervisors assigned to a specific OrangeHRM employee.
    """

    global oauth_token

    if not oauth_token:
        raise HTTPException(
            status_code=401,
            detail="OrangeHRM OAuth token is not available.",
        )

    try:
        return get_employee_supervisors(
            access_token=oauth_token,
            emp_number=emp_number,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# ============================================================
# OrangeHRM Resolved Supervisor API Test
# ============================================================

@app.get("/employees/{emp_number}/resolved-supervisor")
def employee_resolved_supervisor(emp_number: int):
    """Resolve an OrangeHRM supervisor to the business employeeId."""
    global oauth_token
    if not oauth_token:
        raise HTTPException(status_code=401, detail="OrangeHRM OAuth token is not available.")
    try:
        employees_response = get_employees(oauth_token)
        return resolve_employee_supervisor(
            access_token=oauth_token,
            employee_emp_number=emp_number,
            employees_response=employees_response,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ============================================================
# OrangeHRM -> IAM Database Employee Synchronization
# ============================================================

@app.post("/sync/employees")
def sync_employees():
    """
    Synchronize OrangeHRM employees into the IAM database.

    Flow:

        OrangeHRM
            |
            | OAuth2
            v
        Enterprise IAM Platform
            |
            | employee_sync.py
            v
        IAM Database
            |
            | lifecycle detection
            v
        IdentityRequest
    """

    global oauth_token

    # --------------------------------------------------------
    # Verify OAuth authentication
    # --------------------------------------------------------

    if not oauth_token:

        raise HTTPException(
            status_code=401,
            detail=(
                "No OrangeHRM OAuth token available. "
                "Authenticate through /oauth/login first."
            ),
        )

    # --------------------------------------------------------
    # Create IAM database session
    # --------------------------------------------------------

    db = SessionLocal()

    try:

        # ----------------------------------------------------
        # Synchronize employees
        # ----------------------------------------------------

        result = sync_orangehrm_employees(
            access_token=oauth_token,
            db=db,
        )

        return result

    except HTTPException:

        db.rollback()
        raise

    except Exception as exc:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )

    finally:

        db.close()