from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime


class User(BaseModel):
    id: Optional[str] = Field(default=None, description="Document ID")
    name: str
    email: EmailStr
    password_hash: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class AuthSession(BaseModel):
    id: Optional[str] = Field(default=None)
    user_id: str
    token: str
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class SosAlert(BaseModel):
    id: Optional[str] = Field(default=None)
    user_id: str
    status: str = Field(default="open", description="open|resolved")
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    message: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class TrackSession(BaseModel):
    id: Optional[str] = Field(default=None)
    user_id: str
    is_active: bool = True
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None


class LocationUpdate(BaseModel):
    id: Optional[str] = Field(default=None)
    session_id: str
    user_id: str
    latitude: float
    longitude: float
    accuracy: Optional[float] = None
    speed: Optional[float] = None
    heading: Optional[float] = None
    timestamp: Optional[datetime] = None
