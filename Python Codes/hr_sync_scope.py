from app.config.identity_scope import (
    HR_MANAGED_OUS,
    EXCLUDED_ACCOUNTS
)


def is_hr_managed_user(user):

    username = user.get("sAMAccountName","").lower()

    dn = user.get("distinguishedName","")


    # Ignore service/admin accounts
    if username in EXCLUDED_ACCOUNTS:
        return False


    # Only users inside department OUs
    for ou in HR_MANAGED_OUS:

        if ou.lower() in dn.lower():
            return True


    return False