from ninja import NinjaAPI

from orochi.api.routers.auth import router as auth_router
from orochi.api.routers.bookmarks import router as bookmarks_router
from orochi.api.routers.dumps import router as dumps_router
from orochi.api.routers.folders import router as folders_router
from orochi.api.routers.plugins import router as plugins_router
from orochi.api.routers.users import router as users_router
from orochi.api.routers.utils import router as utils_router

api = NinjaAPI(csrf=True, title="Orochi API", urls_namespace="api")
api.add_router("/auth/", auth_router, tags=["Auth"])
api.add_router("/users/", users_router, tags=["Users"])
api.add_router("/folders/", folders_router, tags=["Folders"])
api.add_router("/dumps/", dumps_router, tags=["Dumps"])
api.add_router("/plugins/", plugins_router, tags=["Plugins"])
api.add_router("/utils/", utils_router, tags=["Utils"])
api.add_router("/bookmars/", bookmarks_router, tags=["Bookmars"])
