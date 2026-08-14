# app/config/identity_mapping.py

"""
Identity mapping configuration.

This module defines the authoritative IAM mapping between:

    OrangeHRM Department
        ↓
    Active Directory OU
        ↓
    Birthright AD Security Groups

This file contains IAM business logic only.

It does NOT connect to Active Directory and does NOT
perform provisioning.
"""


# ============================================================
# Active Directory Base DN
# ============================================================

BASE_DN = "DC=Corp,DC=local"


# ============================================================
# Department OU Mapping
# ============================================================
#
# OrangeHRM department
#       ↓
# Active Directory OU
#
# ============================================================

DEPARTMENT_OU_MAPPING = {

    "Accounting":
        "OU=Accounting,"
        "OU=Departments,"
        "DC=Corp,DC=local",

    "Customer Relations":
        "OU=Customer Relations,"
        "OU=Departments,"
        "DC=Corp,DC=local",

    "Engineering":
        "OU=Engineering,"
        "OU=Departments,"
        "DC=Corp,DC=local",

    "Executives":
        "OU=Executives,"
        "OU=Departments,"
        "DC=Corp,DC=local",

    "Finance":
        "OU=Finance,"
        "OU=Departments,"
        "DC=Corp,DC=local",

    "HR":
        "OU=HR,"
        "OU=Departments,"
        "DC=Corp,DC=local",

    "IT":
        "OU=IT,"
        "OU=Departments,"
        "DC=Corp,DC=local",

    "Security":
        "OU=Security,"
        "OU=Departments,"
        "DC=Corp,DC=local",
}


# ============================================================
# Birthright Group Mapping
# ============================================================
#
# These groups are assigned automatically based on department.
#
# Privileged / conditional groups must NOT be placed here.
#
# ============================================================

DEPARTMENT_GROUP_MAPPING = {

    "Accounting": [
        "Accounting Group",
    ],

    "Customer Relations": [
        "Customer Relations Group",
    ],

    "Engineering": [
        "Engineering Group",
    ],

    "Executives": [
        "Executives Group",
    ],

    "Finance": [
        "Finance Group",
    ],

    "HR": [
        "HR Group",
    ],

    "IT": [
        "IT Group",
    ],

    "Security": [
        "Security Group",
    ],
}


# ============================================================
# Group Distinguished Names
# ============================================================
#
# All of your department security groups are currently located
# under:
#
# OU=Domain Groups,DC=Corp,DC=local
#
# ============================================================

GROUP_DN_MAPPING = {

    "Accounting Group":
        "CN=Accounting Group,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",

    "Customer Relations Group":
        "CN=Customer Relations Group,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",

    "Engineering Group":
        "CN=Engineering Group,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",

    "Executives Group":
        "CN=Executives Group,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",

    "Finance Group":
        "CN=Finance Group,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",

    "HR Group":
        "CN=HR Group,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",

    "IT Group":
        "CN=IT Group,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",

    "Security Group":
        "CN=Security Group,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",
}


# ============================================================
# Non-Birthright / Privileged Groups
# ============================================================
#
# These must NEVER be automatically assigned simply because
# of department membership.
#
# ============================================================

PRIVILEGED_GROUPS = {

    "IAM Admins",
    "Privileged Security Admins",
    "Domain Admins",
    "Enterprise Admins",
}


# ============================================================
# Conditional Access Groups
# ============================================================
#
# These require separate approval / business justification.
#
# ============================================================

CONDITIONAL_ACCESS_GROUPS = {

    "Remote Access Users",
    "VPN Users",
}


# ============================================================
# Non-HR Managed OUs
# ============================================================
#
# These identities are outside normal employee lifecycle scope.
#
# ============================================================

NON_HR_MANAGED_OUS = {

    "OU=Contractors,DC=Corp,DC=local",

    "OU=Service Accounts,DC=Corp,DC=local",

    "OU=Privileged Accounts,DC=Corp,DC=local",

    "OU=Disabled Users,DC=Corp,DC=local",
}


# ============================================================
# Contractor Groups
# ============================================================
#
# Contractors are deliberately separate from HR employee RBAC.
#
# Jira-based contractor workflow can use these later.
#
# ============================================================

CONTRACTOR_GROUPS = {

    "Contractor Base Access":
        "CN=Contractor Base Access,"
        "OU=Contractor Groups,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",

    "Contractor VPN Users":
        "CN=Contractor VPN Users,"
        "OU=Contractor Groups,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",

    "Contractor Remote Access":
        "CN=Contractor Remote Access,"
        "OU=Contractor Groups,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",

    "Contractor Project Access":
        "CN=Contractor Project Access,"
        "OU=Contractor Groups,"
        "OU=Domain Groups,"
        "DC=Corp,DC=local",
}


# ============================================================
# Helper Functions
# ============================================================

def get_department_ou(
    department: str | None,
) -> str | None:
    """
    Return the Active Directory OU for a department.
    """

    if not department:
        return None

    return DEPARTMENT_OU_MAPPING.get(
        department
    )


def get_department_groups(
    department: str | None,
) -> list[str]:
    """
    Return birthright groups for a department.
    """

    if not department:
        return []

    return DEPARTMENT_GROUP_MAPPING.get(
        department,
        [],
    )


def get_group_dn(
    group_name: str,
) -> str | None:
    """
    Return the AD distinguished name for a mapped group.
    """

    return GROUP_DN_MAPPING.get(
        group_name
    )


def get_department_group_dns(
    department: str | None,
) -> list[str]:
    """
    Return full AD group DNs for the department's
    birthright access.
    """

    groups = get_department_groups(
        department
    )

    group_dns = []

    for group in groups:

        group_dn = get_group_dn(
            group
        )

        if group_dn:
            group_dns.append(
                group_dn
            )

    return group_dns


def is_privileged_group(
    group_name: str,
) -> bool:
    """
    Determine whether a group is privileged.
    """

    return (
        group_name
        in PRIVILEGED_GROUPS
    )


def is_conditional_access_group(
    group_name: str,
) -> bool:
    """
    Determine whether a group requires separate approval.
    """

    return (
        group_name
        in CONDITIONAL_ACCESS_GROUPS
    )


def validate_department(
    department: str | None,
) -> bool:
    """
    Return True only when the department is configured
    for IAM provisioning.
    """

    if not department:
        return False

    return (
        department
        in DEPARTMENT_OU_MAPPING
    )


def get_identity_mapping(
    department: str | None,
) -> dict:
    """
    Return the complete provisioning mapping for a department.

    Example:

        get_identity_mapping("IT")

    returns:

        {
            "department": "IT",
            "ou": "...",
            "groups": ["IT Group"],
            "group_dns": ["CN=IT Group,..."]
        }
    """

    if not validate_department(
        department
    ):

        raise ValueError(
            (
                "No IAM identity mapping exists "
                f"for department: {department}"
            )
        )

    return {
        "department":
            department,

        "ou":
            get_department_ou(
                department
            ),

        "groups":
            get_department_groups(
                department
            ),

        "group_dns":
            get_department_group_dns(
                department
            ),
    }