"""
Database Schemas for Safegirl Pro

Each Pydantic model corresponds to a MongoDB collection (lowercased class name).
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address (unique)")
    password_hash: str = Field(..., description="Password hash (server-side)")
    password_salt: str = Field(..., description="Password salt (server-side)")
    trusted_contacts: List[EmailStr] = Field(default_factory=list, description="Trusted contact emails")
    is_active: bool = Field(True, description="Active user flag")

class AuthSession(BaseModel):
    user_id: str = Field(..., description="User ID (stringified ObjectId)")
    token: str = Field(..., description="Session token")
    expires_at: datetime = Field(..., description="Token expiry")

class SosAlert(BaseModel):
    user_id: str = Field(..., description="User ID")
    message: Optional[str] = Field(None, description="Optional note")
    lat: float = Field(..., description="Latitude")
    lng: float = Field(..., description="Longitude")
    status: str = Field("active", description="active|resolved|cancelled")

class TrackSession(BaseModel):
    user_id: str = Field(..., description="User ID")
    destination: Optional[str] = Field(None, description="Destination label")
    status: str = Field("active", description="active|stopped")
    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None

class LocationUpdate(BaseModel):
    session_id: str = Field(..., description="Tracking session ID")
    user_id: str = Field(..., description="User ID")
    lat: float = Field(...)
    lng: float = Field(...)
    speed: Optional[float] = None
    heading: Optional[float] = None

# Optional reference schemas retained for tooling examples
class Product(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    category: str
    in_stock: bool = True
