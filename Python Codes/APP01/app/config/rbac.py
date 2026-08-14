"""
Enterprise IAM Platform
Active Directory RBAC Configuration

Maps authoritative OrangeHRM department values to
Active Directory OUs and department security groups.
"""


AD_DOMAIN_DN = "DC=Corp,DC=local"

DEPARTMENTS_OU = f"OU=Departments,{AD_DOMAIN_DN}"

DISABLED_USERS_OU = f"OU=Disabled Users,{AD_DOMAIN_DN}"

CONTRACTORS_OU = f"OU=Contractors,{AD_DOMAIN_DN}"

PRIVILEGED_ACCOUNTS_OU = f"OU=Privileged Accounts,{AD_DOMAIN_DN}"

SERVICE_ACCOUNTS_OU = f"OU=Service Accounts,{AD_DOMAIN_DN}"


DEPARTMENT_RBAC = {

    "Accounting": {
        "ou": f"OU=Accounting,{DEPARTMENTS_OU}",
        "groups": [
            "Accounting Group",
        ],
    },

    "Customer Relations": {
        "ou": f"OU=Customer Relations,{DEPARTMENTS_OU}",
        "groups": [
            "Customer Relations Group",
        ],
    },

    "Engineering": {
        "ou": f"OU=Engineering,{DEPARTMENTS_OU}",
        "groups": [
            "Engineering Group",
        ],
    },

    "Executives": {
        "ou": f"OU=Executives,{DEPARTMENTS_OU}",
        "groups": [
            "Executives Group",
        ],
    },

    "Finance": {
        "ou": f"OU=Finance,{DEPARTMENTS_OU}",
        "groups": [
            "Finance Group",
        ],
    },

    "HR": {
        "ou": f"OU=HR,{DEPARTMENTS_OU}",
        "groups": [
            "HR Group",
        ],
    },

    "IT": {
        "ou": f"OU=IT,{DEPARTMENTS_OU}",
        "groups": [
            "IT Group",
        ],
    },

    "Security": {
        "ou": f"OU=Security,{DEPARTMENTS_OU}",
        "groups": [
            "Security Group",
        ],
    },
}


# Groups that department-mover automation must never
# automatically remove from an identity.
PROTECTED_GROUPS = {
    "Domain Users",
    "IAM Admins",
    "Privileged Security Admins",
    "Remote Access Users",
    "VPN Users",
}


# Department groups controlled by the IAM platform.
MANAGED_DEPARTMENT_GROUPS = {
    "Accounting Group",
    "Customer Relations Group",
    "Engineering Group",
    "Executives Group",
    "Finance Group",
    "HR Group",
    "IT Group",
    "Security Group",
}