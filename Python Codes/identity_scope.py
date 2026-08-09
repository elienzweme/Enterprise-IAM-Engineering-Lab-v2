# Identity lifecycle scope configuration


BASE_DN = "DC=Corp,DC=local"


# ==================================================
# HR MANAGED IDENTITIES
# Employees managed by OrangeHRM
# ==================================================

HR_MANAGED_OUS = [
    "OU=Accounting,OU=Departments,DC=Corp,DC=local",
    "OU=Customer Relations,OU=Departments,DC=Corp,DC=local",
    "OU=Engineering,OU=Departments,DC=Corp,DC=local",
    "OU=Executives,OU=Departments,DC=Corp,DC=local",
    "OU=Finance,OU=Departments,DC=Corp,DC=local",
    "OU=HR,OU=Departments,DC=Corp,DC=local",
    "OU=IT,OU=Departments,DC=Corp,DC=local",
    "OU=Security,OU=Departments,DC=Corp,DC=local",
]


# ==================================================
# NON HR MANAGED IDENTITIES
# These require separate lifecycle workflows
# ==================================================

NON_HR_MANAGED_OUS = [
    "OU=Contractors,DC=Corp,DC=local",
    "OU=Service Accounts,DC=Corp,DC=local",
    "OU=Privileged Accounts,DC=Corp,DC=local",
]


# ==================================================
# Accounts IAM must ignore completely
# ==================================================

EXCLUDED_ACCOUNTS = [

    # Default AD accounts
    "administrator",
    "guest",
    "krbtgt",

    # Service accounts
    "svc_backup",
    "svc_splunk",
    "svc_sql",
    "svc_iam",

    # Privileged admin accounts
    "iam.admin",
    "admin.security",
    "elie.admin",

    # Test/disabled identities
    "disabled.user",
    "testuser",
]


# ==================================================
# Privileged groups
# Never assigned automatically
# ==================================================

PRIVILEGED_GROUPS = [

    "Domain Admins",
    "Enterprise Admins",
    "Privileged Security Admins",
    "IAM Admins",

]


# ==================================================
# Employee Birthright RBAC
# ==================================================

DEPARTMENT_GROUP_MAPPING = {

    "Accounting":
        "Accounting Group",

    "Customer Relations":
        "Customer Relations Group",

    "Engineering":
        "Engineering Group",

    "Executives":
        "Executives Group",

    "Finance":
        "Finance Group",

    "HR":
        "HR Group",

    "IT":
        "IT Group",

    "Security":
        "Security Group",

}


# ==================================================
# Contractor RBAC
# Separate from employee RBAC
# ==================================================

CONTRACTOR_GROUP_MAPPING = {

    "Contractor":
        "Contractor Base Access",

}