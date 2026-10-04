"""
WebSocket Real-Time Live Feed Endpoint for NexusGuard
"""
from typing import List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import json
import asyncio

router = APIRouter(
    tags=["Real-time Feeds"]
)


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                pass


ws_manager = ConnectionManager()


@router.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """
    Live streaming WebSocket connection for instant alerts and new security logs.
    """
    await ws_manager.connect(websocket)
    try:
        # Send initial connection confirmation
        await websocket.send_text(json.dumps({
            "type": "CONNECTION_ESTABLISHED",
            "message": "Connected to NexusGuard Live Event Bus",
            "status": "ONLINE"
        }))
        while True:
            # Keep connection open and respond to client heartbeats
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "PONG"}))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
