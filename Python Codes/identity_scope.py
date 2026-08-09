# Identity lifecycle scope configuration

BASE_DN = "DC=Corp,DC=local"


# HR authoritative identities
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


# Accounts IAM must ignore
EXCLUDED_ACCOUNTS = [
    "administrator",
    "guest",
    "krbtgt",

    "svc_backup",
    "svc_splunk",
    "svc_sql",
    "svc_iam",

    "iam.admin",
    "admin.security",
    "elie.admin",

    "disabled.user",
    "testuser",
]


# Groups that are NOT birthright HR RBAC
PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Privileged Security Admins",
    "IAM Admins",
]


# Birthright RBAC mapping
DEPARTMENT_GROUP_MAPPING = {

    "Accounting": "Accounting Group",

    "Customer Relations": "Customer Relations Group",

    "Engineering": "Engineering Group",

    "Executives": "Executives Group",

    "Finance": "Finance Group",

    "HR": "HR Group",

    "IT": "IT Group",

    "Security": "Security Group",
}