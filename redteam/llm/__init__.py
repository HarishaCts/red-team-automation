"""LLM client abstraction: real Claude API + offline mock backend."""

from .client import LLMClient, build_client

__all__ = ["LLMClient", "build_client"]