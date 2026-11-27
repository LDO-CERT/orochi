import django
import psycopg2
from django.shortcuts import get_object_or_404
from guardian.shortcuts import get_objects_for_user
from ninja import Router, Status

from orochi.api.models import (
    BookmarksEditInSchema,
    BookmarksInSchema,
    BookmarksSchema,
    ErrorsOut,
    SuccessResponse,
)
from orochi.api.security import dual_auth
from orochi.website.models import Bookmark, Dump, Plugin

router = Router()


@router.post(
    "/",
    auth=dual_auth,
    response={201: BookmarksSchema, 400: ErrorsOut},
    url_name="create_bookmark",
)
def create_bookmarks(request, bookmarks_in: BookmarksInSchema):
    """
    Create bookmarks for the user.

    Args:
        request: The request object.
        bookmarks_in: Input data for creating bookmarks.

    Returns:
        Tuple[int, Bookmark]: A tuple containing the status code and the created bookmark.

    Raises:
        400: If an exception occurs during the bookmark creation process.
    """
    if not (bookmarks_in.name or "").strip():
        return Status(400, {"errors": "Bookmark name is required"})
    try:
        indexes = []
        ok_indexes = list(get_objects_for_user(request.user, "website.can_see").values_list("index", flat=True))
        for index_id in bookmarks_in.selected_indexes.split(","):
            index_id = str(index_id)
            if index_id not in ok_indexes:
                continue
            index = get_object_or_404(Dump, index=index_id)
            indexes.append(index)
        if indexes:
            plugin = get_object_or_404(Plugin, name=bookmarks_in.selected_plugin)
            bookmark = Bookmark.objects.create(
                user=request.user,
                plugin=plugin,
                star=bookmarks_in.star,
                # Omitted by API clients: fall back to the model default instead of a NOT NULL error
                icon=bookmarks_in.icon or Bookmark._meta.get_field("icon").default,
                name=bookmarks_in.name,
                query=bookmarks_in.query,
            )
            bookmark.save()
            for index in indexes:
                bookmark.indexes.add(index)
            return Status(201, bookmark)
        return Status(400, {"errors": "No valid indexes selected"})
    except (psycopg2.errors.UniqueViolation, django.db.utils.IntegrityError):
        return Status(400, {"errors": "Bookmark name already used"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.get("/", auth=dual_auth, response=list[BookmarksSchema])
def list_bookmarks(request):
    """
    Retrieves a list of bookmarks for the current user.

    Returns:
        QuerySet: A queryset of bookmarks belonging to the current user.
    """
    return Bookmark.objects.filter(user=request.user)


@router.get(
    "/{int:id}",
    auth=dual_auth,
    response={200: BookmarksSchema, 400: ErrorsOut, 404: ErrorsOut},
    url_name="get_bookmark",
)
def get_bookmark(request, id: int):
    """
    Retrieves a bookmark by its ID.
    """
    bookmark = Bookmark.objects.filter(pk=id, user=request.user).first()
    if not bookmark:
        return Status(404, {"errors": "Bookmark not found."})
    return Status(200, bookmark)


@router.patch(
    "/{int:id}",
    response={200: BookmarksSchema, 400: ErrorsOut, 404: ErrorsOut},
    auth=dual_auth,
    url_name="edit_bookmark",
)
def edit_bookmark(request, id: int, data: BookmarksEditInSchema):
    """
    Edit bookmark.
    """
    bookmark = Bookmark.objects.filter(pk=id, user=request.user).first()
    if not bookmark:
        return Status(404, {"errors": "Bookmark not found."})
    try:
        for attr, value in data.dict(exclude_unset=True).items():
            setattr(bookmark, attr, value)
        bookmark.save()
        return Status(200, bookmark)
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.delete(
    "/{int:id}",
    auth=dual_auth,
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
        return Status(200, {"message": f"Bookmark {name} deleted"})
    except Exception as excp:
        return Status(400, {"errors": str(excp)})


@router.post(
    "/{int:id}/star/{star}",
    auth=dual_auth,
    url_name="star_bookmark",
    response={200: SuccessResponse, 400: ErrorsOut, 404: ErrorsOut},
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
    bookmark = Bookmark.objects.filter(pk=id, user=request.user).first()
    if not bookmark:
        return Status(404, {"errors": "Bookmark not found."})
    try:
        name = bookmark.name
        bookmark.star = star
        bookmark.save()
        return Status(
            200,
            {"message": (f"Bookmark {name} starred" if star else f"Bookmark {name} unstarred")},
        )
    except Exception as excp:
        return Status(400, {"errors": str(excp)})
