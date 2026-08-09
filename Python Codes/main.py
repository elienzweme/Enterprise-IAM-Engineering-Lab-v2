# app/main.py

import secrets

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse

from app.database import SessionLocal

from app.services.orangehrm import (
    build_authorization_url,
    exchange_authorization_code,
    get_employees,
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

    # Generate a random state value.
    oauth_state = secrets.token_urlsafe(32)

    # Build OrangeHRM authorization URL.
    authorization_url = build_authorization_url(
        oauth_state
    )

    # Redirect browser to OrangeHRM.
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

    if state and oauth_state and state != oauth_state:

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

        # Authorization code has been consumed.
        oauth_state = None

        # ----------------------------------------------------
        # Return safe response
        #
        # DO NOT expose the actual token in the browser.
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
        "token_available": oauth_token is not None
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