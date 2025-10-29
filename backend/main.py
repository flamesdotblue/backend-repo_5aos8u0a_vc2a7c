from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, List
from datetime import datetime, timedelta
import hashlib
import secrets

from database import db, create_document, get_documents

app = FastAPI(title="Safegirl Pro API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------- Utility helpers ----------------------

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def get_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return auth_header


def get_user_by_token(auth_header: Optional[str]) -> Optional[Dict]:
    token = get_bearer_token(auth_header)
    if not token:
        return None
    sessions = get_documents("authsession", {"token": token}, limit=1)
    if not sessions:
        return None
    session = sessions[0]
    users = get_documents("user", {"_id": session["user_id"]}, limit=1)
    if users:
        return users[0]
    return None


# ---------------------- Request models ----------------------

class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SosRequest(BaseModel):
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    message: Optional[str] = None


class TrackStartRequest(BaseModel):
    pass


class TrackStopRequest(BaseModel):
    session_id: str


class LocationPostRequest(BaseModel):
    session_id: str
    latitude: float
    longitude: float
    accuracy: Optional[float] = None
    speed: Optional[float] = None
    heading: Optional[float] = None
    timestamp: Optional[datetime] = None


# ---------------------- Basic routes ----------------------

@app.get("/")
def root():
    return {"name": "Safegirl Pro API", "status": "ok", "time": datetime.utcnow().isoformat()}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from Safegirl Pro API"}


@app.get("/test")
def test_db():
    try:
        # Attempt a simple operation: list collections if available
        cols = []
        try:
            cols = db.list_collection_names()  # type: ignore[attr-defined]
        except Exception:
            pass
        return {"ok": True, "collections": cols}
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})


# ---------------------- Auth ----------------------

@app.post("/auth/signup")
def signup(payload: SignupRequest):
    existing = get_documents("user", {"email": payload.email}, limit=1)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
    }
    user = create_document("user", user_doc)
    token = new_token()
    create_document("authsession", {
        "user_id": user["_id"],
        "token": token,
        "expires_at": datetime.utcnow() + timedelta(days=30),
    })
    return {"token": token, "user": {"id": user["_id"], "name": user["name"], "email": user["email"]}}


@app.post("/auth/login")
def login(payload: LoginRequest):
    user_list = get_documents("user", {"email": payload.email}, limit=1)
    if not user_list:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = user_list[0]
    if user.get("password_hash") != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = new_token()
    create_document("authsession", {
        "user_id": user["_id"],
        "token": token,
        "expires_at": datetime.utcnow() + timedelta(days=30),
    })
    return {"token": token, "user": {"id": user["_id"], "name": user["name"], "email": user["email"]}}


@app.get("/auth/me")
def me(request: Request):
    authorization = request.headers.get("Authorization")
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"id": user["_id"], "name": user["name"], "email": user["email"]}


# ---------------------- SOS ----------------------

@app.post("/sos")
def create_sos(payload: SosRequest, request: Request):
    authorization = request.headers.get("Authorization")
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    doc = {
        "user_id": user["_id"],
        "status": "open",
        "latitude": payload.latitude,
        "longitude": payload.longitude,
        "message": payload.message,
    }
    sos = create_document("sosalert", doc)
    return {"id": sos["_id"], "status": sos["status"]}


@app.patch("/sos/{sos_id}/resolve")
def resolve_sos(sos_id: str, request: Request):
    authorization = request.headers.get("Authorization")
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    coll = db["sosalert"]
    result = coll.update_one({"_id": sos_id, "user_id": user["_id"]}, {"$set": {"status": "resolved", "updated_at": datetime.utcnow()}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="SOS not found")
    return {"ok": True}


# ---------------------- Tracking ----------------------

@app.post("/track/start")
def start_track(_: TrackStartRequest, request: Request):
    authorization = request.headers.get("Authorization")
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    session = create_document("tracksession", {"user_id": user["_id"], "is_active": True, "started_at": datetime.utcnow()})
    return {"session_id": session["_id"], "is_active": True}


@app.post("/track/stop")
def stop_track(payload: TrackStopRequest, request: Request):
    authorization = request.headers.get("Authorization")
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    coll = db["tracksession"]
    result = coll.update_one({"_id": payload.session_id, "user_id": user["_id"]}, {"$set": {"is_active": False, "ended_at": datetime.utcnow()}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"ok": True}


@app.post("/track/location")
def post_location(payload: LocationPostRequest, request: Request):
    authorization = request.headers.get("Authorization")
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    sessions = get_documents("tracksession", {"_id": payload.session_id, "user_id": user["_id"]}, limit=1)
    if not sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    loc = create_document("locationupdate", {
        "session_id": payload.session_id,
        "user_id": user["_id"],
        "latitude": payload.latitude,
        "longitude": payload.longitude,
        "accuracy": payload.accuracy,
        "speed": payload.speed,
        "heading": payload.heading,
        "timestamp": payload.timestamp or datetime.utcnow(),
    })
    # Broadcast via websocket if connected
    WebSocketHub.broadcast(payload.session_id, {
        "type": "location",
        "latitude": loc["latitude"],
        "longitude": loc["longitude"],
        "timestamp": loc.get("timestamp"),
    })
    return {"ok": True}


# ---------------------- WebSocket Hub ----------------------

class WebSocketHub:
    rooms: Dict[str, List[WebSocket]] = {}

    @classmethod
    async def connect(cls, session_id: str, ws: WebSocket):
        await ws.accept()
        cls.rooms.setdefault(session_id, []).append(ws)

    @classmethod
    async def disconnect(cls, session_id: str, ws: WebSocket):
        if session_id in cls.rooms and ws in cls.rooms[session_id]:
            cls.rooms[session_id].remove(ws)
            if not cls.rooms[session_id]:
                del cls.rooms[session_id]

    @classmethod
    def broadcast(cls, session_id: str, message: dict):
        if session_id not in cls.rooms:
            return
        dead: List[WebSocket] = []
        for ws in list(cls.rooms[session_id]):
            try:
                # Schedule send without awaiting in sync path
                import anyio
                anyio.from_thread.run(asyncio_run_send, ws, message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            # best-effort cleanup
            try:
                cls.rooms[session_id].remove(ws)
            except Exception:
                pass


async def asyncio_run_send(ws: WebSocket, message: dict):
    try:
        await ws.send_json(message)
    except Exception:
        pass


@app.websocket("/ws/track/{session_id}")
async def ws_track(session_id: str, websocket: WebSocket):
    await WebSocketHub.connect(session_id, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            if isinstance(data, dict) and data.get("type") == "ping":
                await websocket.send_json({"type": "pong", "t": datetime.utcnow().isoformat()})
    except WebSocketDisconnect:
        await WebSocketHub.disconnect(session_id, websocket)

