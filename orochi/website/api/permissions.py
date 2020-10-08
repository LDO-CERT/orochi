from rest_framework import permissions
from guardian.shortcuts import get_objects_for_user


## Custom permissions
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
        For object user must have permission
        """
        return (
            request.user
            and request.user.is_authenticated
            and obj in get_objects_for_user(request.user, "website.can_see")
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