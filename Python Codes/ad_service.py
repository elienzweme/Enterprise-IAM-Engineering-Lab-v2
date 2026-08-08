import os

from dotenv import load_dotenv
from ldap3 import ALL, Connection, Server, Tls

load_dotenv()


AD_SERVER = os.getenv("AD_SERVER")
AD_PORT = int(os.getenv("AD_PORT", "636"))
AD_USE_SSL = os.getenv("AD_USE_SSL", "true").lower() == "true"
AD_BASE_DN = os.getenv("AD_BASE_DN")
AD_BIND_USER = os.getenv("AD_BIND_USER")
AD_BIND_PASSWORD = os.getenv("AD_BIND_PASSWORD")


def get_ad_connection() -> Connection:
    """
    Create and bind a connection to Active Directory.

    This function currently performs only authentication
    and read operations.
    """

    server = Server(
        AD_SERVER,
        port=AD_PORT,
        use_ssl=AD_USE_SSL,
        get_info=ALL,
    )

    connection = Connection(
        server,
        user=AD_BIND_USER,
        password=AD_BIND_PASSWORD,
        auto_bind=True,
    )

    return connection


def test_ad_connection() -> dict:
    """
    Test whether APP01 can authenticate to Active Directory.
    """

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


def get_user_by_employee_id(employee_id: str) -> dict | None:
    """
    Find an Active Directory user using the employeeID attribute.
    """

    connection = get_ad_connection()

    try:
        search_filter = (
            f"(&(objectCategory=person)"
            f"(objectClass=user)"
            f"(employeeID={employee_id}))"
        )

        attributes = [
            "displayName",
            "givenName",
            "sn",
            "sAMAccountName",
            "userPrincipalName",
            "employeeID",
            "department",
            "title",
            "mail",
            "memberOf",
            "userAccountControl",
        ]

        connection.search(
            search_base=AD_BASE_DN,
            search_filter=search_filter,
            attributes=attributes,
        )

        if not connection.entries:
            return None

        entry = connection.entries[0]

        user_account_control = (
            int(entry.userAccountControl.value)
            if entry.userAccountControl.value is not None
            else 0
        )

        enabled = not bool(user_account_control & 2)

        groups = []

        if entry.memberOf.value:
            if isinstance(entry.memberOf.value, list):
                groups = entry.memberOf.value
            else:
                groups = [entry.memberOf.value]

        return {
            "distinguished_name": entry.entry_dn,
            "display_name": entry.displayName.value,
            "first_name": entry.givenName.value,
            "last_name": entry.sn.value,
            "sam_account_name": entry.sAMAccountName.value,
            "user_principal_name": entry.userPrincipalName.value,
            "employee_id": entry.employeeID.value,
            "department": entry.department.value,
            "title": entry.title.value,
            "email": entry.mail.value,
            "enabled": enabled,
            "groups": groups,
        }

    finally:
        connection.unbind()