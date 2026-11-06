from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    email: EmailStr
    role: str


class InvestigationRequest(BaseModel):
    text: str = Field(min_length=1, max_length=12000)
    input_type: Literal["text", "sms", "whatsapp", "url", "email", "conversation", "payment_request", "transaction"] = "text"


class FeedbackRequest(BaseModel):
    investigation_id: UUID
    rating: Literal["correct", "incorrect", "uncertain"]
    comment: str | None = Field(default=None, max_length=1000)


class InvestigationSummary(BaseModel):
    id: UUID
    category: str
    risk_score: int
    risk_level: str
    created_at: datetime
