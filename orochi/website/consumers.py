import json
import logging

from channels.generic.websocket import AsyncWebsocketConsumer


class NotifyConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # User connects to his update channel
        self.room_name = self.scope["url_route"]["kwargs"]["user_id"]
        self.room_group_name = f"chat_{self.room_name}"
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        logging.info(f"User connected to {self.room_group_name} - {self.channel_name}")
        await self.accept()

    async def disconnect(self, close_code):
        # User leaves room group
        logging.info(
            f"User disconnected from {self.room_group_name} - {self.channel_name}"
        )
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        # Receive message from WebSocket
        text_data_json = json.loads(text_data)

        # Send message to room group
        await self.channel_layer.group_send(
            self.room_group_name,
            {"type": "chat_message", "message": text_data_json["message"]},
        )

    async def chat_message(self, event):
        # Receive message from room group
        await self.send(text_data=json.dumps({"message": event["message"]}))
