from django.contrib.auth.models import Group

ROLE_ADMIN = "Admin"
ROLE_ANALYST = "Analyst"
ROLE_REVIEWER = "Reviewer"
ROLE_READONLY = "ReadOnly"

ALL_ROLES = [ROLE_ADMIN, ROLE_ANALYST, ROLE_REVIEWER, ROLE_READONLY]

ROLE_CHOICES = (
    (ROLE_ADMIN, "Admin"),
    (ROLE_ANALYST, "Analyst"),
    (ROLE_REVIEWER, "Reviewer"),
    (ROLE_READONLY, "ReadOnly"),
)

ROLE_HIERARCHY = {
    ROLE_ADMIN: 40,
    ROLE_ANALYST: 30,
    ROLE_REVIEWER: 20,
    ROLE_READONLY: 10,
}


def ensure_default_groups():
    """Ensure all default Orochi role groups exist."""
    for role_name in ALL_ROLES:
        Group.objects.get_or_create(name=role_name)


def get_user_role(user) -> str:
    """
    Resolve effective role for a user based on superuser/staff status and group memberships.
    Defaults to Analyst for backward compatibility with standard users.
    """
    if not user or not user.is_authenticated:
        return ROLE_READONLY

    if user.is_superuser or user.is_staff:
        return ROLE_ADMIN

    # Check explicit group memberships in order of precedence
    user_groups = set(user.groups.values_list("name", flat=True))
    if ROLE_ADMIN in user_groups:
        return ROLE_ADMIN
    if ROLE_READONLY in user_groups:
        return ROLE_READONLY
    if ROLE_REVIEWER in user_groups:
        return ROLE_REVIEWER
    if ROLE_ANALYST in user_groups:
        return ROLE_ANALYST

    # Default role for existing/standard users without groups
    return ROLE_ANALYST


def has_role(user, min_role: str) -> bool:
    """
    Check whether the user's role satisfies the minimum required role.
    """
    user_role = get_user_role(user)
    user_level = ROLE_HIERARCHY.get(user_role, 0)
    min_level = ROLE_HIERARCHY.get(min_role, ROLE_HIERARCHY[ROLE_ANALYST])
    return user_level >= min_level


def can_execute_plugin(user, plugin) -> bool:
    """
    Determine if a user has permission to execute a specific plugin:
    1. Unauthenticated or ReadOnly users are forbidden.
    2. Disabled plugins cannot be executed.
    3. Superusers can always execute non-disabled plugins.
    4. Per-user UserPlugin.can_execute overrides (True/False) take highest precedence.
    5. Otherwise falls back to user role hierarchy vs plugin.min_role.
    """
    if not user or not user.is_authenticated:
        return False

    if getattr(plugin, "disabled", False):
        return False

    if getattr(user, "is_superuser", False):
        return True

    user_role = get_user_role(user)
    if user_role == ROLE_READONLY:
        return False

    # Check per-user explicit override if UserPlugin exists
    from orochi.website.models import UserPlugin

    user_plugin = UserPlugin.objects.filter(user=user, plugin=plugin).first()
    if user_plugin and user_plugin.can_execute is not None:
        return bool(user_plugin.can_execute)

    # Fallback to role check
    plugin_min_role = getattr(plugin, "min_role", ROLE_ANALYST)
    return has_role(user, plugin_min_role)


def set_user_role(user, role_name: str):
    """
    Assign a user to one of the Orochi roles, managing group memberships.
    """
    if role_name not in ALL_ROLES:
        raise ValueError(f"Invalid role: {role_name}. Must be one of {ALL_ROLES}")

    ensure_default_groups()

    # Remove user from all standard role groups
    for r in ALL_ROLES:
        try:
            g = Group.objects.get(name=r)
            user.groups.remove(g)
        except Group.DoesNotExist:
            pass

    # Add user to target role group
    target_group = Group.objects.get(name=role_name)
    user.groups.add(target_group)

    if role_name == ROLE_ADMIN:
        user.is_staff = True
    elif not user.is_superuser:
        user.is_staff = False

    user.save()
    return role_name
