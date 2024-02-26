from django.urls import re_path

from orochi.website.consumers import NotifyConsumer

websocket_urlpatterns = [
    re_path(r"ws/notify/(?P<user_id>\w+)/$", NotifyConsumer.as_asgi()),
]
