"""
HR Identity Scope Management

This module determines which Active Directory identities
are managed by the HR/IAM lifecycle process.

Identity populations:

1. HR Managed Employees
   - Source: OrangeHRM
   - Location: OU=Departments
   - Lifecycle: Joiner / Mover / Leaver

2. Contractors
   - Source: Jira / Request Workflow (future)
   - Location: OU=Contractors
   - Lifecycle: Contractor onboarding/offboarding

3. Service Accounts
   - Location: OU=Service Accounts
   - Lifecycle: Manual management

4. Privileged Accounts
   - Location: OU=Privileged Accounts
   - Lifecycle: Privileged access workflow

Only HR-managed employees are processed by employee_sync.py.
"""


from app.config.identity_scope import (
    HR_MANAGED_OUS,
    NON_HR_MANAGED_OUS,
    EXCLUDED_ACCOUNTS
)



def is_excluded_account(username):
    """
    Determines whether an account should never
    be managed by HR IAM automation.

    Examples:
        administrator
        svc_iam
        iam.admin
    """

    if not username:
        return True

    return username.lower() in EXCLUDED_ACCOUNTS



def is_hr_managed_user(user):
    """
    Determines whether an Active Directory user
    belongs to the HR-managed employee population.

    Returns:

        True:
            User is an employee managed by OrangeHRM

        False:
            User is contractor, service account,
            privileged account, test account,
            or excluded identity
    """

    username = user.get(
        "sAMAccountName",
        ""
    ).lower()


    distinguished_name = user.get(
        "distinguishedName",
        ""
    ).lower()


    # -----------------------------------------
    # Exclude technical/admin identities
    # -----------------------------------------

    if is_excluded_account(username):
        return False



    # -----------------------------------------
    # Only process HR-managed employee OUs
    # -----------------------------------------

    for ou in HR_MANAGED_OUS:

        if ou.lower() in distinguished_name:
            return True



    # -----------------------------------------
    # Everything else is outside HR scope
    # -----------------------------------------

    return False



def is_non_hr_managed_user(user):
    """
    Determines whether a user belongs to
    a non-HR managed identity population.

    Examples:

        Contractors
        Service Accounts
        Privileged Accounts
    """

    distinguished_name = user.get(
        "distinguishedName",
        ""
    ).lower()


    for ou in NON_HR_MANAGED_OUS:

        if ou.lower() in distinguished_name:
            return True


    return False



def filter_hr_users(users):
    """
    Filters a list of AD users.

    Input:
        [
            {
                "sAMAccountName": "john.williams",
                "distinguishedName":
                "CN=John Williams,OU=IT,OU=Departments..."
            }
        ]

    Output:

        Only HR-managed employees
    """

    hr_users = []


    for user in users:

        if is_hr_managed_user(user):

            hr_users.append(user)


    return hr_users



def filter_non_hr_users(users):
    """
    Filters contractor/service/privileged identities.

    This is reserved for future workflows:
        - Contractor onboarding
        - Service account management
        - PAM workflows
    """

    non_hr_users = []


    for user in users:

        if is_non_hr_managed_user(user):

            non_hr_users.append(user)


    return non_hr_users