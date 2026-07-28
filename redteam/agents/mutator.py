"""Mutation agent — produces a stronger variant of an attack that under-performed.

The mutation engine is what makes coverage "self-improving": prompts that scored
at or above a configured threshold (but did not fully breach) are fed back in
with the judge's reasoning so the LLM can craft a transformed retry.
"""

from __future__ import annotations

import logging

from ..categories import AttackCategory
from ..config import LLMConfig
from ..llm.client import LLMClient
from ..llm.prompts import build_mutator_prompt
from ..models import AttackPrompt
from ._parsing import parse_json_object

log = logging.getLogger(__name__)


class MutatorAgent:
    """Generates a single mutated variant from a parent attack prompt."""

    def __init__(self, client: LLMClient, cfg: LLMConfig) -> None:
        self._client = client
        self._cfg = cfg

    async def mutate(
        self,
        category: AttackCategory,
        parent: AttackPrompt,
        judge_reasoning: str,
    ) -> AttackPrompt | None:
        """Return a mutated child prompt, or ``None`` if mutation failed.

        The child records its ``parent_id``, incremented ``mutation_round``, and
        the technique applied — preserving full lineage for the report.
        """
        system, user = build_mutator_prompt(category, parent.prompt, judge_reasoning)
        resp = await self._client.complete(
            model=self._cfg.mutator_model,
            system=system,
            messages=[{"role": "user", "content": user}],
            max_tokens=self._cfg.max_tokens,
            temperature=self._cfg.temperature,
        )

        try:
            data = parse_json_object(resp.text)
        except ValueError:
            log.warning("Mutator output unparseable for parent %s; skipping", parent.id)
            return None

        mutated_text = str(data.get("prompt", "")).strip()
        if not mutated_text:
            return None

        return AttackPrompt(
            category=category.key,
            variant=parent.variant,
            prompt=mutated_text,
            rationale=str(data.get("rationale", "")),
            parent_id=parent.id,
            mutation_round=parent.mutation_round + 1,
            mutation_technique=str(data.get("technique", "unspecified")),
        )