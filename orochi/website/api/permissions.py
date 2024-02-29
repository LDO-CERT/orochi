from guardian.shortcuts import get_objects_for_user
from rest_framework import permissions


# Custom permissions
class NotUpdateAndIsAuthenticated(permissions.IsAuthenticated):
    def has_permission(self, request, view):
        """
        Update are not available so all (other) operations are ok for everyone
        """
        return (
            view.action not in ["update", "partial_update"] or request.user.is_superuser
        )


class AuthAndAuthorized(NotUpdateAndIsAuthenticated):
    def has_object_permission(self, request, view, obj):
        """
        For object user must have can_see permission to list it,
        also not being readonly to edit/delete
        """
        if view.action in ["retrieve", "list"]:
            return (
                request.user
                and request.user.is_authenticated
                and obj in get_objects_for_user(request.user, "website.can_see")
            )
        else:
            return (
                request.user
                and request.user.is_authenticated
                and obj in get_objects_for_user(request.user, "website.can_see")
                and not request.user.groups.filter(name="ReadOnly").exists()
            )


class ParentAuthAndAuthorized(NotUpdateAndIsAuthenticated):
    def has_object_permission(self, request, view, obj):
        """
        For object user must have permission on parent dump
        """
        return (
            request.user
            and request.user.is_authenticated
            and obj.dump in get_objects_for_user(request.user, "website.can_see")
        )


class GrandParentAuthAndAuthorized(NotUpdateAndIsAuthenticated):
    def has_object_permission(self, request, view, obj):
        """
        For object user must have permission on grand parent dump
        """
        return (
            request.user
            and request.user.is_authenticated
            and obj.result.dump in get_objects_for_user(request.user, "website.can_see")
        )
