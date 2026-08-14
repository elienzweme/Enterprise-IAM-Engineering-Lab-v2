# app/services/ad_service.py

import os
import re
import secrets
import ssl
import string

from dotenv import load_dotenv
from ldap3 import (
    ALL,
    MODIFY_ADD,
    MODIFY_DELETE,
    MODIFY_REPLACE,
    Connection,
    Server,
    Tls,
)
from ldap3.utils.conv import escape_filter_chars

load_dotenv()


# ============================================================
# Environment
# ============================================================

AD_SERVER = os.getenv("AD_SERVER")
AD_PORT = int(os.getenv("AD_PORT", "636"))
AD_USE_SSL = os.getenv("AD_USE_SSL", "true").lower() == "true"

AD_BASE_DN = os.getenv("AD_BASE_DN")
AD_BIND_USER = os.getenv("AD_BIND_USER")
AD_BIND_PASSWORD = os.getenv("AD_BIND_PASSWORD")

AD_DOMAIN = os.getenv("AD_DOMAIN", "corp.local")
AD_UPN_SUFFIX = os.getenv("AD_UPN_SUFFIX", AD_DOMAIN)

AD_USERS_OU = os.getenv("AD_USERS_OU", AD_BASE_DN)
AD_DISABLED_USERS_OU = os.getenv("AD_DISABLED_USERS_OU")

# Random JOINER temporary-password length.
# No fixed/default employee password is stored in .env.
AD_TEMP_PASSWORD_LENGTH = int(
    os.getenv("AD_TEMP_PASSWORD_LENGTH", "20")
)


# ============================================================
# Connection
# ============================================================

def get_ad_connection() -> Connection:
    """
    Create and bind a secure connection to Active Directory.

    Password reset operations against AD require a protected
    LDAP channel. In this lab AD_USE_SSL should remain true and
    AD_PORT should normally be 636.
    """

    if not AD_SERVER:
        raise ValueError("AD_SERVER is not configured.")

    if not AD_BASE_DN:
        raise ValueError("AD_BASE_DN is not configured.")

    if not AD_BIND_USER:
        raise ValueError("AD_BIND_USER is not configured.")

    if not AD_BIND_PASSWORD:
        raise ValueError("AD_BIND_PASSWORD is not configured.")

    if not AD_USE_SSL:
        raise RuntimeError(
            "AD password-management operations require a protected "
            "LDAP connection. Set AD_USE_SSL=true and use LDAPS."
        )

    # LAB NOTE:
    # CERT_NONE is convenient for an internal lab with a private/self-signed
    # DC certificate. For production, install/trust the issuing CA and change
    # this to ssl.CERT_REQUIRED.
    tls_configuration = Tls(
        validate=ssl.CERT_NONE,
    )

    server = Server(
        AD_SERVER,
        port=AD_PORT,
        use_ssl=AD_USE_SSL,
        tls=tls_configuration,
        get_info=ALL,
    )

    connection = Connection(
        server,
        user=AD_BIND_USER,
        password=AD_BIND_PASSWORD,
        auto_bind=True,
        raise_exceptions=False,
    )

    if not connection.bound:
        raise ConnectionError(
            "Unable to bind to Active Directory: "
            f"{connection.result}"
        )

    return connection


def test_ad_connection() -> dict:
    """Test whether APP01 can authenticate to Active Directory."""

    connection = get_ad_connection()

    try:
        return {
            "connected": connection.bound,
            "server": AD_SERVER,
            "port": AD_PORT,
            "ssl": AD_USE_SSL,
            "base_dn": AD_BASE_DN,
            "bind_user": AD_BIND_USER,
        }
    finally:
        connection.unbind()


# ============================================================
# Naming helpers
# ============================================================

def _normalize_name_component(value: str) -> str:
    """
    Normalize a name for sAMAccountName/UPN use.

    firstname.lastname remains the convention.
    """
    value = (value or "").strip().lower()
    value = re.sub(r"\s+", "", value)
    value = re.sub(r"[^a-z0-9._-]", "", value)
    return value


def generate_sam_account_name(
    first_name: str,
    last_name: str,
) -> str:
    """Generate firstname.lastname."""

    first = _normalize_name_component(first_name)
    last = _normalize_name_component(last_name)

    if not first or not last:
        raise ValueError(
            "first_name and last_name are required to generate "
            "sAMAccountName."
        )

    return f"{first}.{last}"


def build_user_principal_name(
    sam_account_name: str,
) -> str:
    return f"{sam_account_name}@{AD_UPN_SUFFIX}"


def build_display_name(
    first_name: str,
    last_name: str,
) -> str:
    return f"{first_name.strip()} {last_name.strip()}".strip()


def build_cn(
    first_name: str,
    last_name: str,
) -> str:
    return build_display_name(first_name, last_name)


# ============================================================
# Password helpers
# ============================================================

def generate_temporary_password(
    length: int | None = None,
) -> str:
    """
    Generate a cryptographically secure one-time temporary password.

    Guarantees at least one:
      - uppercase
      - lowercase
      - digit
      - special character

    The password must never be written to application/audit logs.
    """

    length = length or AD_TEMP_PASSWORD_LENGTH

    if length < 16:
        raise ValueError(
            "AD_TEMP_PASSWORD_LENGTH must be at least 16."
        )

    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*_-+="

    chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special),
    ]

    alphabet = uppercase + lowercase + digits + special

    chars.extend(
        secrets.choice(alphabet)
        for _ in range(length - 4)
    )

    secrets.SystemRandom().shuffle(chars)

    return "".join(chars)


# ============================================================
# Lookup helpers
# ============================================================

def _entry_groups(entry) -> list[str]:
    try:
        value = entry.memberOf.value
    except Exception:
        return []

    if not value:
        return []

    if isinstance(value, list):
        return list(value)

    return [value]


def _entry_to_user_dict(entry) -> dict:
    uac_value = getattr(
        getattr(entry, "userAccountControl", None),
        "value",
        0,
    )

    user_account_control = int(uac_value or 0)

    def attr(name):
        item = getattr(entry, name, None)
        return getattr(item, "value", None)

    return {
        "distinguished_name": entry.entry_dn,
        "display_name": attr("displayName"),
        "first_name": attr("givenName"),
        "last_name": attr("sn"),
        "sam_account_name": attr("sAMAccountName"),
        "user_principal_name": attr("userPrincipalName"),
        "employee_id": attr("employeeID"),
        "department": attr("department"),
        "title": attr("title"),
        "email": attr("mail"),
        "manager": attr("manager"),
        "enabled": not bool(user_account_control & 2),
        "groups": _entry_groups(entry),
    }


def _user_attributes() -> list[str]:
    return [
        "displayName",
        "givenName",
        "sn",
        "sAMAccountName",
        "userPrincipalName",
        "employeeID",
        "department",
        "title",
        "mail",
        "manager",
        "memberOf",
        "userAccountControl",
    ]


def get_user_by_employee_id(
    employee_id: str,
) -> dict | None:
    """Find an Active Directory user using employeeID."""

    safe_employee_id = escape_filter_chars(
        str(employee_id)
    )

    connection = get_ad_connection()

    try:
        connection.search(
            search_base=AD_BASE_DN,
            search_filter=(
                "(&(objectCategory=person)"
                "(objectClass=user)"
                f"(employeeID={safe_employee_id}))"
            ),
            attributes=_user_attributes(),
        )

        if not connection.entries:
            return None

        return _entry_to_user_dict(
            connection.entries[0]
        )
    finally:
        connection.unbind()


def get_user_by_sam_account_name(
    sam_account_name: str,
) -> dict | None:
    """Find a user by sAMAccountName."""

    safe_name = escape_filter_chars(
        sam_account_name
    )

    connection = get_ad_connection()

    try:
        connection.search(
            search_base=AD_BASE_DN,
            search_filter=(
                "(&(objectCategory=person)"
                "(objectClass=user)"
                f"(sAMAccountName={safe_name}))"
            ),
            attributes=_user_attributes(),
        )

        if not connection.entries:
            return None

        return _entry_to_user_dict(
            connection.entries[0]
        )
    finally:
        connection.unbind()



def get_users_by_name(
    first_name: str,
    last_name: str,
) -> list[dict]:
    """
    Find exact givenName + sn matches for guarded legacy-account correlation.

    Multiple matches are intentionally returned so the provisioning layer can
    block ambiguous correlation instead of guessing.
    """
    safe_first = escape_filter_chars((first_name or "").strip())
    safe_last = escape_filter_chars((last_name or "").strip())

    if not safe_first or not safe_last:
        return []

    connection = get_ad_connection()
    try:
        connection.search(
            search_base=AD_BASE_DN,
            search_filter=(
                "(&(objectCategory=person)"
                "(objectClass=user)"
                f"(givenName={safe_first})"
                f"(sn={safe_last}))"
            ),
            attributes=_user_attributes(),
        )
        return [_entry_to_user_dict(entry) for entry in connection.entries]
    finally:
        connection.unbind()


def set_ad_employee_id(
    sam_account_name: str,
    employee_id: str,
) -> dict:
    """
    Backfill employeeID on an existing Active Directory account.

    Safety controls:
      - The sAMAccountName must already exist.
      - If the account already has the requested employeeID, this is a no-op.
      - If the account has a different employeeID, refuse to overwrite it.
      - If another AD account already owns the requested employeeID, refuse
        the change to prevent duplicate identity correlation.
    """

    sam_account_name = str(sam_account_name).strip()
    employee_id = str(employee_id).strip()

    if not sam_account_name:
        raise ValueError("sam_account_name is required.")

    if not employee_id:
        raise ValueError("employee_id is required.")

    candidate = get_user_by_sam_account_name(
        sam_account_name
    )

    if not candidate:
        raise ValueError(
            "Active Directory account does not exist for "
            f"sAMAccountName '{sam_account_name}'."
        )

    existing_employee_id = candidate.get(
        "employee_id"
    )

    if existing_employee_id:
        if str(existing_employee_id).strip() == employee_id:
            return {
                "success": True,
                "changed": False,
                "sam_account_name": sam_account_name,
                "employee_id": employee_id,
                "distinguished_name": candidate.get(
                    "distinguished_name"
                ),
                "message": "employeeID is already assigned.",
            }

        raise RuntimeError(
            "AD identity correlation conflict: "
            f"sAMAccountName '{sam_account_name}' already has "
            f"employeeID '{existing_employee_id}', but HR supplied "
            f"'{employee_id}'. Manual review is required."
        )

    employee_id_owner = get_user_by_employee_id(
        employee_id
    )

    if employee_id_owner:
        owner_sam = employee_id_owner.get(
            "sam_account_name"
        )

        if (
            str(owner_sam or "").lower()
            != sam_account_name.lower()
        ):
            raise RuntimeError(
                "AD identity correlation conflict: "
                f"employeeID '{employee_id}' is already assigned to "
                f"'{owner_sam}'. Manual review is required."
            )

    user_dn = candidate.get(
        "distinguished_name"
    )

    if not user_dn:
        raise RuntimeError(
            f"AD user '{sam_account_name}' has no distinguished name."
        )

    connection = get_ad_connection()

    try:
        success = connection.modify(
            user_dn,
            {
                "employeeID": [
                    (
                        MODIFY_REPLACE,
                        [employee_id],
                    )
                ]
            },
        )

        if not success:
            raise RuntimeError(
                "Failed to backfill AD employeeID: "
                f"{connection.result}"
            )

        return {
            "success": True,
            "changed": True,
            "sam_account_name": sam_account_name,
            "employee_id": employee_id,
            "distinguished_name": user_dn,
        }

    finally:
        connection.unbind()


def reconcile_ad_identity(
    employee_id: str,
    first_name: str,
    last_name: str,
) -> dict:
    """
    Correlate an authoritative HR identity to AD safely.

    Order:
      1. employeeID
      2. expected sAMAccountName (firstname.lastname)
      3. unique exact givenName + sn legacy-account match

    A different employeeID is never overwritten and ambiguous name matches
    always require manual review.
    """
    employee_id = str(employee_id).strip()
    if not employee_id:
        raise ValueError("employee_id is required.")

    expected_sam = generate_sam_account_name(first_name, last_name)

    ad_user = get_user_by_employee_id(employee_id)
    if ad_user:
        return {
            "ad_user": ad_user,
            "exists": True,
            "correlation_method": "employeeID",
            "employee_id_backfilled": False,
            "legacy_account_adopted": False,
            "sam_account_name": ad_user.get("sam_account_name") or expected_sam,
        }

    candidate = get_user_by_sam_account_name(expected_sam)
    if candidate:
        existing_id = str(candidate.get("employee_id") or "").strip()
        if existing_id and existing_id != employee_id:
            raise RuntimeError(
                f"AD identity conflict: '{expected_sam}' already has "
                f"employeeID '{existing_id}', not '{employee_id}'."
            )

        backfilled = False
        if not existing_id:
            set_ad_employee_id(expected_sam, employee_id)
            backfilled = True
            candidate = get_user_by_employee_id(employee_id)
            if not candidate:
                raise RuntimeError("employeeID backfill completed but re-read failed.")

        return {
            "ad_user": candidate,
            "exists": True,
            "correlation_method": "sAMAccountName",
            "employee_id_backfilled": backfilled,
            "legacy_account_adopted": backfilled,
            "sam_account_name": expected_sam,
        }

    matches = get_users_by_name(first_name, last_name)

    if len(matches) > 1:
        sams = ", ".join(
            sorted(str(item.get("sam_account_name") or "<unknown>") for item in matches)
        )
        raise RuntimeError(
            f"Ambiguous AD identity correlation for '{first_name} {last_name}': "
            f"{sams}. Manual review is required."
        )

    if len(matches) == 1:
        candidate = matches[0]
        candidate_sam = candidate.get("sam_account_name")
        if not candidate_sam:
            raise RuntimeError("Legacy AD candidate has no sAMAccountName.")

        existing_id = str(candidate.get("employee_id") or "").strip()
        if existing_id and existing_id != employee_id:
            raise RuntimeError(
                f"Legacy account '{candidate_sam}' matches the HR name but "
                f"already has employeeID '{existing_id}', not '{employee_id}'."
            )

        backfilled = False
        if not existing_id:
            set_ad_employee_id(candidate_sam, employee_id)
            backfilled = True
            candidate = get_user_by_employee_id(employee_id)
            if not candidate:
                raise RuntimeError("Legacy-account adoption completed but re-read failed.")

        return {
            "ad_user": candidate,
            "exists": True,
            "correlation_method": "name",
            "employee_id_backfilled": backfilled,
            "legacy_account_adopted": True,
            "sam_account_name": candidate_sam,
        }

    return {
        "ad_user": None,
        "exists": False,
        "correlation_method": None,
        "employee_id_backfilled": False,
        "legacy_account_adopted": False,
        "sam_account_name": expected_sam,
    }


# ============================================================
# JOINER - Create account
# ============================================================

def create_ad_user(
    employee_id: str,
    first_name: str,
    last_name: str,
    department: str | None = None,
    job_title: str | None = None,
    email: str | None = None,
    target_ou: str | None = None,
    sam_account_name: str | None = None,
) -> dict:
    """
    Create a new AD user DISABLED.

    Password setup, first-logon password-change enforcement, group
    assignment, and enablement are separate controlled JOINER steps.
    """

    employee_id = str(employee_id)

    if get_user_by_employee_id(employee_id):
        raise ValueError(
            f"Employee {employee_id} already exists in Active Directory."
        )

    if not sam_account_name:
        sam_account_name = generate_sam_account_name(
            first_name,
            last_name,
        )

    existing_username = get_user_by_sam_account_name(
        sam_account_name
    )

    if existing_username:
        raise ValueError(
            "sAMAccountName already exists: "
            f"{sam_account_name}"
        )

    destination_ou = target_ou or AD_USERS_OU

    if not destination_ou:
        raise ValueError("No target OU configured.")

    display_name = build_display_name(
        first_name,
        last_name,
    )

    cn = build_cn(
        first_name,
        last_name,
    )

    user_dn = f"CN={cn},{destination_ou}"
    upn = build_user_principal_name(
        sam_account_name
    )

    attributes = {
        "givenName": first_name,
        "sn": last_name,
        "displayName": display_name,
        "sAMAccountName": sam_account_name,
        "userPrincipalName": upn,
        "employeeID": employee_id,

        # NORMAL_ACCOUNT (512) + ACCOUNTDISABLE (2)
        "userAccountControl": 514,
    }

    if department:
        attributes["department"] = department

    if job_title:
        attributes["title"] = job_title

    if email:
        attributes["mail"] = email

    connection = get_ad_connection()

    try:
        success = connection.add(
            dn=user_dn,
            object_class=[
                "top",
                "person",
                "organizationalPerson",
                "user",
            ],
            attributes=attributes,
        )

        if not success:
            raise RuntimeError(
                "Active Directory user creation failed: "
                f"{connection.result}"
            )

        return {
            "success": True,
            "action": "JOINER",
            "operation": "CREATE_AD_USER",
            "employee_id": employee_id,
            "distinguished_name": user_dn,
            "sam_account_name": sam_account_name,
            "user_principal_name": upn,
            "enabled": False,
        }
    finally:
        connection.unbind()


# ============================================================
# Password management
# ============================================================

def set_ad_password(
    employee_id: str,
    password: str,
) -> dict:
    """
    Administrator-reset the password for an AD user over LDAPS.

    The plaintext password is intentionally never returned.
    """

    if not password:
        raise ValueError("Password cannot be empty.")

    ad_user = get_user_by_employee_id(
        str(employee_id)
    )

    if not ad_user:
        raise ValueError(
            f"Employee {employee_id} does not exist in Active Directory."
        )

    user_dn = ad_user["distinguished_name"]

    connection = get_ad_connection()

    try:
        success = connection.extend.microsoft.modify_password(
            user=user_dn,
            new_password=password,
        )

        if not success:
            raise RuntimeError(
                "Failed to set AD password: "
                f"{connection.result}"
            )

        return {
            "success": True,
            "employee_id": str(employee_id),
            "sam_account_name": ad_user.get(
                "sam_account_name"
            ),
            "password_set": True,
        }
    finally:
        connection.unbind()


def require_password_change_at_next_logon(
    employee_id: str,
) -> dict:
    """
    Force password change at next logon by setting pwdLastSet=0.
    """

    ad_user = get_user_by_employee_id(
        str(employee_id)
    )

    if not ad_user:
        raise ValueError(
            f"Employee {employee_id} does not exist in Active Directory."
        )

    connection = get_ad_connection()

    try:
        success = connection.modify(
            ad_user["distinguished_name"],
            {
                "pwdLastSet": [
                    (
                        MODIFY_REPLACE,
                        [0],
                    )
                ]
            },
        )

        if not success:
            raise RuntimeError(
                "Failed to require password change at next logon: "
                f"{connection.result}"
            )

        return {
            "success": True,
            "employee_id": str(employee_id),
            "must_change_password": True,
        }
    finally:
        connection.unbind()


# ============================================================
# MOVER - Update attributes
# ============================================================

def update_ad_user(
    employee_id: str,
    department: str | None = None,
    job_title: str | None = None,
    email: str | None = None,
) -> dict:
    """Update supplied attributes for an existing AD user."""

    ad_user = get_user_by_employee_id(
        str(employee_id)
    )

    if not ad_user:
        raise ValueError(
            f"Employee {employee_id} does not exist in Active Directory."
        )

    changes = {}

    if department is not None:
        changes["department"] = [
            (MODIFY_REPLACE, [department])
        ]

    if job_title is not None:
        changes["title"] = [
            (MODIFY_REPLACE, [job_title])
        ]

    if email is not None:
        if email:
            changes["mail"] = [
                (MODIFY_REPLACE, [email])
            ]
        else:
            changes["mail"] = [
                (MODIFY_REPLACE, [])
            ]

    if not changes:
        return {
            "success": True,
            "employee_id": str(employee_id),
            "message": "No attributes supplied.",
        }

    connection = get_ad_connection()

    try:
        success = connection.modify(
            ad_user["distinguished_name"],
            changes,
        )

        if not success:
            raise RuntimeError(
                "Failed to update AD user: "
                f"{connection.result}"
            )

        return {
            "success": True,
            "employee_id": str(employee_id),
            "attributes_updated": list(
                changes.keys()
            ),
        }
    finally:
        connection.unbind()


# ============================================================
# Account enable / disable
# ============================================================

def enable_ad_user(
    employee_id: str,
) -> dict:
    """
    Enable an existing AD account.

    A valid password should be set before this function is called.
    """

    ad_user = get_user_by_employee_id(
        str(employee_id)
    )

    if not ad_user:
        raise ValueError(
            f"Employee {employee_id} does not exist in Active Directory."
        )

    if ad_user.get("enabled"):
        return {
            "success": True,
            "employee_id": str(employee_id),
            "enabled": True,
            "message": "Account is already enabled.",
        }

    connection = get_ad_connection()

    try:
        connection.search(
            search_base=ad_user["distinguished_name"],
            search_filter="(objectClass=user)",
            attributes=["userAccountControl"],
        )

        if not connection.entries:
            raise RuntimeError(
                "Unable to read userAccountControl."
            )

        current_uac = int(
            connection.entries[0]
            .userAccountControl
            .value
        )

        new_uac = current_uac & ~2

        success = connection.modify(
            ad_user["distinguished_name"],
            {
                "userAccountControl": [
                    (
                        MODIFY_REPLACE,
                        [new_uac],
                    )
                ]
            },
        )

        if not success:
            raise RuntimeError(
                "Failed to enable AD account: "
                f"{connection.result}"
            )

        return {
            "success": True,
            "employee_id": str(employee_id),
            "sam_account_name": ad_user.get(
                "sam_account_name"
            ),
            "enabled": True,
        }
    finally:
        connection.unbind()


def disable_ad_user(
    employee_id: str,
) -> dict:
    """Disable an existing AD account without deleting it."""

    ad_user = get_user_by_employee_id(
        str(employee_id)
    )

    if not ad_user:
        raise ValueError(
            f"Employee {employee_id} does not exist in Active Directory."
        )

    if not ad_user.get("enabled"):
        return {
            "success": True,
            "employee_id": str(employee_id),
            "enabled": False,
            "message": "Account is already disabled.",
        }

    connection = get_ad_connection()

    try:
        connection.search(
            search_base=ad_user["distinguished_name"],
            search_filter="(objectClass=user)",
            attributes=["userAccountControl"],
        )

        if not connection.entries:
            raise RuntimeError(
                "Unable to read userAccountControl."
            )

        current_uac = int(
            connection.entries[0]
            .userAccountControl
            .value
        )

        new_uac = current_uac | 2

        success = connection.modify(
            ad_user["distinguished_name"],
            {
                "userAccountControl": [
                    (
                        MODIFY_REPLACE,
                        [new_uac],
                    )
                ]
            },
        )

        if not success:
            raise RuntimeError(
                "Failed to disable AD account: "
                f"{connection.result}"
            )

        return {
            "success": True,
            "employee_id": str(employee_id),
            "enabled": False,
        }
    finally:
        connection.unbind()


# ============================================================
# Group membership
# ============================================================

def add_user_to_group(
    employee_id: str,
    group_dn: str,
) -> dict:
    """Add an AD user to a security group. Idempotent."""

    ad_user = get_user_by_employee_id(
        str(employee_id)
    )

    if not ad_user:
        raise ValueError(
            f"Employee {employee_id} does not exist in Active Directory."
        )

    normalized_groups = {
        group.lower()
        for group in ad_user.get("groups", [])
    }

    if group_dn.lower() in normalized_groups:
        return {
            "success": True,
            "employee_id": str(employee_id),
            "group_dn": group_dn,
            "already_member": True,
        }

    connection = get_ad_connection()

    try:
        success = connection.modify(
            group_dn,
            {
                "member": [
                    (
                        MODIFY_ADD,
                        [
                            ad_user[
                                "distinguished_name"
                            ]
                        ],
                    )
                ]
            },
        )

        if not success:
            raise RuntimeError(
                "Failed to add AD user to group: "
                f"{connection.result}"
            )

        return {
            "success": True,
            "employee_id": str(employee_id),
            "group_dn": group_dn,
            "already_member": False,
        }
    finally:
        connection.unbind()


def remove_user_from_group(
    employee_id: str,
    group_dn: str,
) -> dict:
    """Remove an AD user from a security group. Idempotent."""

    ad_user = get_user_by_employee_id(
        str(employee_id)
    )

    if not ad_user:
        raise ValueError(
            f"Employee {employee_id} does not exist in Active Directory."
        )

    normalized_groups = {
        group.lower()
        for group in ad_user.get("groups", [])
    }

    if group_dn.lower() not in normalized_groups:
        return {
            "success": True,
            "employee_id": str(employee_id),
            "group_dn": group_dn,
            "was_member": False,
        }

    connection = get_ad_connection()

    try:
        success = connection.modify(
            group_dn,
            {
                "member": [
                    (
                        MODIFY_DELETE,
                        [
                            ad_user[
                                "distinguished_name"
                            ]
                        ],
                    )
                ]
            },
        )

        if not success:
            raise RuntimeError(
                "Failed to remove AD user from group: "
                f"{connection.result}"
            )

        return {
            "success": True,
            "employee_id": str(employee_id),
            "group_dn": group_dn,
            "was_member": True,
        }
    finally:
        connection.unbind()


# ============================================================
# OU movement
# ============================================================

def move_ad_user(
    employee_id: str,
    target_ou: str,
) -> dict:
    """Move an existing AD user to another OU."""

    ad_user = get_user_by_employee_id(
        str(employee_id)
    )

    if not ad_user:
        raise ValueError(
            f"Employee {employee_id} does not exist in Active Directory."
        )

    old_dn = ad_user["distinguished_name"]

    # Already in target OU.
    if old_dn.lower().endswith(
        "," + target_ou.lower()
    ):
        return {
            "success": True,
            "employee_id": str(employee_id),
            "old_dn": old_dn,
            "new_dn": old_dn,
            "already_in_target_ou": True,
        }

    current_rdn = old_dn.split(",", 1)[0]

    connection = get_ad_connection()

    try:
        success = connection.modify_dn(
            dn=old_dn,
            relative_dn=current_rdn,
            new_superior=target_ou,
        )

        if not success:
            raise RuntimeError(
                "Failed to move AD user: "
                f"{connection.result}"
            )

        new_dn = f"{current_rdn},{target_ou}"

        return {
            "success": True,
            "employee_id": str(employee_id),
            "old_dn": old_dn,
            "new_dn": new_dn,
            "already_in_target_ou": False,
        }
    finally:
        connection.unbind()


# ============================================================
# Identity / Manager Helpers
# ============================================================

def ad_identity_exists(employee_id: str) -> bool:
    """Return True when employeeID already exists in Active Directory."""
    return get_user_by_employee_id(str(employee_id)) is not None


def set_ad_manager(
    employee_id: str,
    manager_employee_id: str | None,
) -> dict:
    """Set or clear the AD manager attribute using employeeID correlation."""
    employee_id = str(employee_id)
    employee = get_user_by_employee_id(employee_id)
    if not employee:
        raise ValueError(f"Employee {employee_id} does not exist in Active Directory.")

    employee_dn = employee.get("distinguished_name")
    if not employee_dn:
        raise RuntimeError(f"Employee {employee_id} has no distinguished name.")

    connection = get_ad_connection()
    try:
        if not manager_employee_id:
            if not employee.get("manager"):
                return {"success": True, "changed": False, "employee_id": employee_id, "manager_employee_id": None, "manager_dn": None}
            success = connection.modify(employee_dn, {"manager": [(MODIFY_REPLACE, [])]})
            if not success:
                raise RuntimeError(f"Failed to clear AD manager: {connection.result}")
            return {"success": True, "changed": True, "employee_id": employee_id, "manager_employee_id": None, "manager_dn": None}

        manager_employee_id = str(manager_employee_id)
        if manager_employee_id == employee_id:
            raise ValueError("An employee cannot be assigned as their own manager.")

        manager = get_user_by_employee_id(manager_employee_id)
        if not manager:
            raise ValueError(f"Manager employee {manager_employee_id} does not exist in Active Directory.")
        manager_dn = manager.get("distinguished_name")
        if not manager_dn:
            raise RuntimeError(f"Manager employee {manager_employee_id} has no distinguished name.")

        current_manager = employee.get("manager")
        if current_manager and current_manager.lower() == manager_dn.lower():
            return {"success": True, "changed": False, "employee_id": employee_id, "manager_employee_id": manager_employee_id, "manager_dn": manager_dn}

        success = connection.modify(employee_dn, {"manager": [(MODIFY_REPLACE, [manager_dn])]})
        if not success:
            raise RuntimeError(f"Failed to update AD manager: {connection.result}")
        return {"success": True, "changed": True, "employee_id": employee_id, "manager_employee_id": manager_employee_id, "manager_dn": manager_dn}
    finally:
        connection.unbind()
