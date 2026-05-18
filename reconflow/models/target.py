"""Target model."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from reconflow.core.validator import detect_target_type


TargetType = Literal["domain", "ip", "url", "invalid"]


class Target(BaseModel):
    value: str = Field(min_length=1)
    kind: TargetType = "invalid"

    @field_validator("value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        return value.strip()

    @classmethod
    def from_value(cls, value: str) -> "Target":
        normalized_value = value.strip()
        return cls(value=normalized_value, kind=detect_target_type(normalized_value))
