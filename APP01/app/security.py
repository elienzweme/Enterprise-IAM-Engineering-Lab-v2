
"""Inbound API-key authentication and role authorization."""

from dataclasses import dataclass
import os
import secrets

from dotenv import load_dotenv

from fastapi import (
    Depends,
    HTTPException,
    status,
)

from fastapi.security import APIKeyHeader


load_dotenv()


API_KEY_ENV_NAMES = (
    "IAM_VIEWER_API_KEY",
    "IAM_SYNC_API_KEY",
    "IAM_APPROVER_API_KEY",
    "IAM_PROVISIONER_API_KEY",
    "IAM_ADMIN_API_KEY",
)


@dataclass(frozen=True)
class ApiPrincipal:
    """Authenticated APP01 API identity."""

    subject: str
    roles: frozenset[str]


@dataclass(frozen=True)
class ApiCredential:
    """Internal API-key-to-principal mapping."""

    api_key: str
    principal: ApiPrincipal


API_KEY_HEADER = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
    description=(
        "APP01 API key. Keys are stored only in "
        "the server-side .env file."
    ),
)


_KEY_DEFINITIONS = (
    (
        "IAM_VIEWER_API_KEY",
        "iam.viewer",
        {
            "iam.viewer",
        },
    ),
    (
        "IAM_SYNC_API_KEY",
        "orangehrm.sync",
        {
            "iam.sync",
        },
    ),
    (
        "IAM_APPROVER_API_KEY",
        "iam.approver",
        {
            "iam.viewer",
            "iam.approver",
        },
    ),
    (
        "IAM_PROVISIONER_API_KEY",
        "iam.provisioner",
        {
            "iam.viewer",
            "iam.provisioner",
        },
    ),
    (
        "IAM_ADMIN_API_KEY",
        "iam.admin",
        {
            "iam.viewer",
            "iam.sync",
            "iam.approver",
            "iam.provisioner",
            "iam.admin",
        },
    ),
)


def configured_credentials() -> list[ApiCredential]:
    """
    Build the configured credential list.

    Values are read from process environment variables and are
    never returned by an API endpoint or written to logs.
    """

    credentials = []

    for env_name, subject, roles in _KEY_DEFINITIONS:
        api_key = os.getenv(
            env_name,
            "",
        ).strip()

        if not api_key:
            continue

        credentials.append(
            ApiCredential(
                api_key=api_key,
                principal=ApiPrincipal(
                    subject=subject,
                    roles=frozenset(roles),
                ),
            )
        )

    return credentials


def authenticate_api_key(
    api_key: str | None = Depends(
        API_KEY_HEADER
    ),
) -> ApiPrincipal:
    """
    Authenticate the X-API-Key header.

    Returns the authenticated identity without returning or
    logging the supplied credential.
    """

    credentials = configured_credentials()

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "APP01 API authentication is not configured."
            ),
        )

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key.",
            headers={
                "WWW-Authenticate": "ApiKey",
            },
        )

    for credential in credentials:
        if secrets.compare_digest(
            api_key,
            credential.api_key,
        ):
            return credential.principal

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key.",
        headers={
            "WWW-Authenticate": "ApiKey",
        },
    )


def require_roles(
    *required_roles: str,
):
    """
    Create a FastAPI dependency requiring one of the specified
    roles. The iam.admin role is always authorized.
    """

    allowed = frozenset(
        role.strip()
        for role in required_roles
        if role.strip()
    )

    if not allowed:
        raise ValueError(
            "At least one required role must be specified."
        )

    def authorize(
        principal: ApiPrincipal = Depends(
            authenticate_api_key
        ),
    ) -> ApiPrincipal:
        if (
            "iam.admin" not in principal.roles
            and principal.roles.isdisjoint(
                allowed
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "Authenticated identity does not have "
                    "the required role."
                ),
            )

        return principal

    return authorize
