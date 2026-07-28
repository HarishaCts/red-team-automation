"""Typed configuration loading and validation.

Configuration is layered: values come from a YAML file, and secrets/overrides
come from environment variables (and an optional `.env` file). The loader
produces a fully-validated :class:`Config` object; the rest of the codebase never
touches raw dicts or ``os.environ`` directly.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal, Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field, field_validator

from .models import RiskScore

# Load `.env` once at import time so ANTHROPIC_API_KEY etc. are available.
load_dotenv()


class LLMConfig(BaseModel):
    """Provider selection and per-role model settings."""

    provider: Literal["auto", "anthropic", "mock"] = "auto"
    attacker_model: str = "claude-sonnet-5"
    judge_model: str = "claude-opus-4-8"
    mutator_model: str = "claude-sonnet-5"
    reporter_model: str = "claude-opus-4-8"
    max_tokens: int = 2048
    temperature: float = 1.0
    request_timeout_seconds: int = 60
    max_retries: int = 4

    def resolve_provider(self) -> Literal["anthropic", "mock"]:
        """Turn ``auto`` into a concrete backend based on key availability.

        Returns ``"anthropic"`` only when an API key is actually present;
        otherwise falls back to the offline mock so the tool always runs.
        """
        if self.provider == "anthropic":
            return "anthropic"
        if self.provider == "mock":
            return "mock"
        # provider == "auto"
        return "anthropic" if os.getenv("ANTHROPIC_API_KEY") else "mock"


class TargetConfig(BaseModel):
    """The system under test."""

    name: str = "Target LLM"
    model: str = "claude-sonnet-5"
    system_prompt: str = ""
    # If set, calls go to this external OpenAI-compatible/Anthropic endpoint
    # instead of the configured provider. `api_key_env` names the env var that
    # holds that endpoint's key.
    endpoint: Optional[str] = None
    api_key_env: Optional[str] = None


class MutationConfig(BaseModel):
    enabled: bool = True
    max_rounds: int = 2
    mutate_if_score_at_least: RiskScore = RiskScore.LOW

    @field_validator("mutate_if_score_at_least", mode="before")
    @classmethod
    def _coerce_score(cls, v: object) -> object:
        # Allow lowercase strings from YAML (e.g. "low") to map to the enum.
        if isinstance(v, str):
            return v.lower()
        return v


class CampaignConfig(BaseModel):
    categories: list[str] = Field(default_factory=list)
    variants_per_category: int = 5
    max_concurrency: int = 8
    mutation: MutationConfig = Field(default_factory=MutationConfig)


class StorageConfig(BaseModel):
    sqlite_path: str = "./redteam.db"

    @property
    def database_url(self) -> str:
        """Effective DB URL. A postgres DSN in the env overrides SQLite."""
        env_url = os.getenv("REDTEAM_DATABASE_URL")
        if env_url:
            return env_url
        return f"sqlite:///{self.sqlite_path}"


class ReportConfig(BaseModel):
    output_dir: str = "./reports"
    formats: list[Literal["markdown", "json"]] = Field(
        default_factory=lambda: ["markdown", "json"]
    )


class Config(BaseModel):
    """Root configuration object."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    target: TargetConfig = Field(default_factory=TargetConfig)
    campaign: CampaignConfig = Field(default_factory=CampaignConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        """Load configuration from a YAML file.

        If ``path`` is None or missing, returns a config built entirely from
        defaults (which, combined with ``auto`` provider selection, still yields
        a runnable mock campaign).
        """
        if path is None:
            return cls()
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        with p.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return cls.model_validate(raw)