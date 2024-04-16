from typing import List

from django.shortcuts import get_object_or_404
from ninja import Router
from ninja.security import django_auth

from orochi.api.models import BookmarksSchema, ErrorsOut, SuccessResponse
from orochi.website.models import Bookmark

router = Router()


@router.get("/", auth=django_auth, response=List[BookmarksSchema])
def list_bookmarks(request):
    """
    Retrieves a list of bookmarks for the current user.

    Returns:
        QuerySet: A queryset of bookmarks belonging to the current user.
    """
    return Bookmark.objects.filter(user=request.user)


@router.delete(
    "/{int:id}",
    auth=django_auth,
    url_name="delete_bookmark",
    response={200: SuccessResponse, 400: ErrorsOut},
)
def delete_bookmarks(request, id: int):
    """
    Deletes a bookmark by its ID.

    Args:
        id (int): The ID of the bookmark to delete.

    Returns:
        tuple: A tuple containing the status code and a message dictionary.

    Raises:
        Exception: If an error occurs during the deletion process.
    """
    bookmark = get_object_or_404(Bookmark, pk=id, user=request.user)
    name = bookmark.name
    try:
        bookmark.delete()
        return 200, {"message": f"Bookmark {name} deleted"}
    except Exception as excp:
        return 400, {"errors": str(excp)}


@router.post(
    "/{int:id}/star/{star}",
    auth=django_auth,
    url_name="star_bookmark",
    response={200: SuccessResponse, 400: ErrorsOut},
)
def star_bookmark(request, id: int, star: bool):
    """
    Stars or unstars a bookmark.

    Args:
        id (int): The ID of the bookmark to star/unstar.
        star (bool): True to star the bookmark, False to unstar it.

    Returns:
        tuple: A tuple containing the HTTP status code and a message dict.

    Raises:
        Exception: If an error occurs during the process.
    """
    try:
        bookmark = get_object_or_404(Bookmark, pk=id, user=request.user)
        name = bookmark.name
        bookmark.star = star
        bookmark.save()
        return 200, {
            "message": (
                f"Bookmark {name} starred" if star else f"Bookmark {name} unstarred"
            )
        }
    except Exception as excp:
        return 400, {"errors": str(excp)}
