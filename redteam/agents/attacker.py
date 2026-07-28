"""Attacker agent — generates adversarial prompt variants for a category."""

from __future__ import annotations

import logging

from ..categories import AttackCategory
from ..config import LLMConfig
from ..llm.client import LLMClient
from ..llm.prompts import build_attacker_prompt
from ..models import AttackPrompt
from ._parsing import parse_json_array

log = logging.getLogger(__name__)


class AttackerAgent:
    """Uses the LLM to synthesize adversarial prompts against a target."""

    def __init__(self, client: LLMClient, cfg: LLMConfig) -> None:
        self._client = client
        self._cfg = cfg

    async def generate(
        self,
        category: AttackCategory,
        target_system_prompt: str,
        n: int,
    ) -> list[AttackPrompt]:
        """Generate up to ``n`` adversarial prompts for ``category``.

        Robust to malformed model output: individual bad array elements are
        skipped rather than aborting the whole category.
        """
        system, user = build_attacker_prompt(category, target_system_prompt, n)
        resp = await self._client.complete(
            model=self._cfg.attacker_model,
            system=system,
            messages=[{"role": "user", "content": user}],
            max_tokens=self._cfg.max_tokens,
            temperature=self._cfg.temperature,
        )

        try:
            raw_items = parse_json_array(resp.text)
        except ValueError:
            log.warning("Attacker returned unparseable output for %s; skipping", category.key)
            return []

        prompts: list[AttackPrompt] = []
        for idx, item in enumerate(raw_items, start=1):
            if not isinstance(item, dict) or "prompt" not in item:
                continue
            prompts.append(
                AttackPrompt(
                    category=category.key,
                    variant=int(item.get("variant", idx)),
                    prompt=str(item["prompt"]),
                    rationale=str(item.get("rationale", "")),
                    mutation_round=0,
                )
            )
        log.info("Attacker generated %d prompts for %s", len(prompts), category.key)
        return prompts