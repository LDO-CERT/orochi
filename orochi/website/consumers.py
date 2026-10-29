import contextlib
import json
import logging
import time

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer

logger = logging.getLogger(__name__)


class NotifyConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope.get("user")

        # 1. Enforce session authentication
        if not user or not user.is_authenticated:
            logger.warning("Unauthenticated WebSocket connection rejected: %s", self.scope.get("client"))
            await self.close(code=4401)
            return

        # 2. Extract requested room user ID
        requested_user_id = self.scope["url_route"]["kwargs"].get("user_id")

        # 3. Enforce identity parity (user can only listen to their own updates, unless staff)
        if not user.is_staff and str(user.pk) != str(requested_user_id):
            logger.warning(
                "User %s attempted unauthorized join to room of user %s",
                user.pk,
                requested_user_id,
            )
            await self.close(code=4403)
            return

        self.room_name = str(requested_user_id)
        self.room_group_name = f"chat_{self.room_name}"

        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        logger.info("Authenticated user %s connected to %s", user.pk, self.room_group_name)
        await self.accept()

    async def disconnect(self, close_code):
        if hasattr(self, "room_group_name"):
            logger.info("User disconnected from %s", self.room_group_name)
            await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        # Notify channel is strictly outbound server-to-client notifications
        logger.warning("Ignoring client-sent WebSocket message from user %s", self.scope.get("user"))
        await self.send(text_data=json.dumps({"error": "Direct message broadcasting disabled."}))

    async def chat_message(self, event):
        # Receive message from room group and forward to client
        await self.send(text_data=json.dumps({"message": event["message"]}))


class CasePresenceConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer managing real-time analyst presence within a Case workspace.
    Broadcasts active collaborators and their current analysis focus.
    """

    async def connect(self):
        self.case_id = self.scope["url_route"]["kwargs"].get("case_id")
        self.user = self.scope.get("user")
        self.room_group = f"presence_case_{self.case_id}"

        # 1. Enforce session authentication
        if not self.user or not self.user.is_authenticated:
            logger.warning("Unauthenticated CasePresence connection rejected: %s", self.scope.get("client"))
            await self.close(code=4401)
            return

        # 2. Enforce case access authorization
        can_access = await self.check_case_access(self.case_id, self.user)
        if not can_access:
            logger.warning(
                "User %s attempted unauthorized access to Case %s presence",
                self.user.pk,
                self.case_id,
            )
            await self.close(code=4403)
            return

        await self.channel_layer.group_add(self.room_group, self.channel_name)
        await self.accept()

        await self.update_and_broadcast_presence("Overview")

    @database_sync_to_async
    def check_case_access(self, case_id, user):
        from django.db.models import Q

        from orochi.website.models import Case

        if user.is_superuser or user.is_staff:
            return Case.objects.filter(pk=case_id).exists()
        return Case.objects.filter(
            Q(user=user) | Q(collaborators=user),
            pk=case_id,
        ).exists()

    async def disconnect(self, close_code):
        if hasattr(self, "room_group"):
            await self.remove_presence()
            await self.channel_layer.group_discard(self.room_group, self.channel_name)

    async def receive(self, text_data):
        with contextlib.suppress(Exception):
            data = json.loads(text_data)
            focus = data.get("focus", "Overview")
            await self.update_and_broadcast_presence(focus)

    async def update_and_broadcast_presence(self, focus):
        from django.core.cache import cache

        key = f"case_presence_{self.case_id}"
        presence_map = cache.get(key) or {}
        now = time.time()
        presence_map[str(self.user.pk)] = {
            "username": self.user.username,
            "user_id": self.user.pk,
            "focus": focus,
            "timestamp": now,
        }
        active = [v for v in presence_map.values() if now - v.get("timestamp", 0) < 60]
        cache.set(key, {k: v for k, v in presence_map.items() if now - v.get("timestamp", 0) < 60}, timeout=120)

        await self.channel_layer.group_send(
            self.room_group,
            {"type": "presence_update", "users": active},
        )

    async def remove_presence(self):
        from django.core.cache import cache

        key = f"case_presence_{self.case_id}"
        presence_map = cache.get(key) or {}
        presence_map.pop(str(self.user.pk), None)
        cache.set(key, presence_map, timeout=120)
        await self.channel_layer.group_send(
            self.room_group,
            {"type": "presence_update", "users": list(presence_map.values())},
        )

    async def presence_update(self, event):
        await self.send(text_data=json.dumps(event))
