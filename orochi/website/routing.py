from django.urls import re_path

from orochi.website.consumers import CasePresenceConsumer, NotifyConsumer

websocket_urlpatterns = [
    re_path(r"ws/notify/(?P<user_id>\w+)/$", NotifyConsumer.as_asgi()),
    re_path(r"ws/case/(?P<case_id>\w+)/presence/$", CasePresenceConsumer.as_asgi()),
]
