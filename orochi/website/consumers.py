import json

from channels.generic.websocket import AsyncWebsocketConsumer


class NotifyConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # User connects to his update channel
        self.room_name = self.scope["url_route"]["kwargs"]["user_id"]
        self.room_group_name = f"chat_{self.room_name}"
        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        # User leaves room group
        await self.channel_layer.group_discard(self.room_group_name, self.channel_name)

    async def receive(self, text_data):
        # Receive message from WebSocket
        text_data_json = json.loads(text_data)
        message = text_data_json["message"]

        # Send message to room group
        await self.channel_layer.group_send(
            self.room_group_name, {"type": "chat_message", "message": message}
        )

    async def chat_message(self, event):
        # Receive message from room group
        message = event["message"]
        await self.send(text_data=json.dumps({"message": message}))
