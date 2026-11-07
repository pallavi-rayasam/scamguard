from datetime import datetime
from decimal import Decimal
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator


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


class ConversationMessageInput(BaseModel):
    sender: str = Field(default="participant", min_length=1, max_length=80)
    text: str = Field(min_length=1, max_length=2000)


class ConversationRequest(BaseModel):
    messages: list[ConversationMessageInput] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def limit_total_text(self):
        if sum(len(item.sender) + len(item.text) for item in self.messages) > 12000:
            raise ValueError("Conversation text must be at most 12,000 characters")
        return self


class TransactionRequest(BaseModel):
    description: str = Field(min_length=1, max_length=2000)
    claimed_recipient: str = Field(default="", max_length=160)
    reason: str = Field(default="", max_length=300)
    amount: Decimal | None = Field(default=None, ge=0, le=100000000)
    related_chat: str = Field(default="", max_length=6000)


class FeedbackRequest(BaseModel):
    investigation_id: UUID
    rating: Literal["correct", "incorrect", "uncertain"]
    comment: str | None = Field(default=None, max_length=1000)


class InvestigationSummary(BaseModel):
    id: UUID
    category: str | None
    risk_score: int
    risk_level: str
    created_at: datetime
