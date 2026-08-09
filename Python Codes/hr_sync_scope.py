from app.config.identity_scope import (
    HR_MANAGED_OUS,
    EXCLUDED_ACCOUNTS
)


def is_hr_managed_user(user):
    """
    Determines whether an Active Directory user
    is managed by the HR/IAM lifecycle process.

    Returns:
        True  -> HR managed employee
        False -> Service account, admin account, test account, or outside HR scope
    """

    username = user.get("sAMAccountName", "").lower()
    distinguished_name = user.get("distinguishedName", "")


    # -----------------------------------------
    # Exclude technical / privileged identities
    # -----------------------------------------
    if username in EXCLUDED_ACCOUNTS:
        return False


    # -----------------------------------------
    # Only include users inside HR-managed OUs
    # -----------------------------------------
    for ou in HR_MANAGED_OUS:

        if ou.lower() in distinguished_name.lower():
            return True


    # -----------------------------------------
    # Everything else is excluded
    # -----------------------------------------
    return False



def filter_hr_users(users):
    """
    Filters a list of AD users and returns
    only HR-managed identities.

    Example input:
        [
            {
              "sAMAccountName": "john.williams",
              "distinguishedName":
              "CN=John Williams,OU=IT,OU=Departments,DC=Corp,DC=local"
            }
        ]

    Example output:
        Same list but only HR-managed users.
    """

    hr_users = []

    for user in users:

        if is_hr_managed_user(user):
            hr_users.append(user)


    return hr_users