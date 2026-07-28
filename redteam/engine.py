"""Async orchestration engine — the agentic red-teaming loop.

Pipeline per adversarial prompt:

    attacker.generate  ->  target.execute  ->  judge.judge  ->  [mutator.mutate]*

All prompts run concurrently under a bounded semaphore so a large campaign does
not overwhelm the API or the target. Results are streamed to an optional async
callback (used by the dashboard for a live feed) and persisted to the store.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from .agents import AttackerAgent, JudgeAgent, MutatorAgent, ReporterAgent
from .categories import AttackCategory, resolve_categories
from .config import Config
from .db import Store, build_store
from .llm.client import LLMClient, build_client
from .llm.prompts import build_target_prompt
from .models import (
    AttackPrompt,
    AttackResult,
    Campaign,
    RiskScore,
    SCORE_ORDER,
    TargetResponse,
)

log = logging.getLogger(__name__)

# Optional callback invoked with each completed result (for live dashboards).
ResultCallback = Callable[[AttackResult], Awaitable[None]]


class RedTeamEngine:
    """Coordinates the attacker, target, judge, mutator, and reporter."""

    def __init__(self, cfg: Config, *, store: Optional[Store] = None) -> None:
        self._cfg = cfg
        # A single shared client is fine: the SDK is async and connection-pooled.
        self._client: LLMClient = build_client(cfg.llm)
        self._attacker = AttackerAgent(self._client, cfg.llm)
        self._judge = JudgeAgent(self._client, cfg.llm)
        self._mutator = MutatorAgent(self._client, cfg.llm)
        self._reporter = ReporterAgent(self._client, cfg.llm)
        self._store = store or build_store(cfg.storage)
        # Bound total in-flight LLM work across the whole campaign.
        self._sem = asyncio.Semaphore(cfg.campaign.max_concurrency)

    # -- lifecycle ------------------------------------------------------------
    async def __aenter__(self) -> "RedTeamEngine":
        await self._store.init()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()
        await self._store.aclose()

    # -- main entrypoint ------------------------------------------------------
    async def run_campaign(
        self, on_result: Optional[ResultCallback] = None
    ) -> tuple[Campaign, list[AttackResult]]:
        """Execute a full campaign and return the campaign + all results."""
        categories = resolve_categories(self._cfg.campaign.categories)
        campaign = Campaign(
            target_name=self._cfg.target.name,
            target_model=self._cfg.target.model,
            provider=self._client.provider_name,
            categories=[c.key for c in categories],
            variants_per_category=self._cfg.campaign.variants_per_category,
        )
        await self._store.create_campaign(campaign)
        log.info(
            "Campaign %s started: provider=%s categories=%s",
            campaign.id, campaign.provider, campaign.categories,
        )

        # 1) Generate adversarial prompts for every category (in parallel).
        gen_tasks = [
            self._attacker.generate(
                cat, self._cfg.target.system_prompt,
                self._cfg.campaign.variants_per_category,
            )
            for cat in categories
        ]
        generated = await asyncio.gather(*gen_tasks)
        cat_by_key = {c.key: c for c in categories}

        # 2) Execute + judge every prompt concurrently. Mutation is handled
        #    inline so a mutated child runs as soon as its parent is judged.
        pipeline_tasks = [
            self._process_prompt(cat_by_key[cat.key], prompt, campaign, on_result)
            for cat, prompts in zip(categories, generated)
            for prompt in prompts
        ]
        nested = await asyncio.gather(*pipeline_tasks)
        results: list[AttackResult] = [r for sublist in nested for r in sublist]

        # 3) Finalize campaign metadata.
        campaign.finished_at = datetime.now(timezone.utc)
        campaign.total_attacks = len(results)
        campaign.total_breaches = sum(1 for r in results if r.is_breach)
        await self._store.finalize_campaign(campaign)
        log.info(
            "Campaign %s finished: %d attacks, %d breaches",
            campaign.id, campaign.total_attacks, campaign.total_breaches,
        )
        return campaign, results

    # -- per-prompt pipeline --------------------------------------------------
    async def _process_prompt(
        self,
        category: AttackCategory,
        prompt: AttackPrompt,
        campaign: Campaign,
        on_result: Optional[ResultCallback],
    ) -> list[AttackResult]:
        """Execute + judge a prompt, then run the mutation loop if warranted.

        Returns every result produced from this seed prompt (the original plus
        any mutated descendants).
        """
        produced: list[AttackResult] = []

        result = await self._execute_and_judge(category, prompt)
        produced.append(result)
        await self._persist_and_emit(campaign.id, result, on_result)

        # Mutation loop: keep transforming while the attack is "interesting"
        # (>= threshold) but not already maximal, up to max_rounds.
        mcfg = self._cfg.campaign.mutation
        current = result
        while (
            mcfg.enabled
            and current.attack.mutation_round < mcfg.max_rounds
            and self._should_mutate(current.judgement.score, mcfg.mutate_if_score_at_least)
        ):
            child = await self._mutator.mutate(
                category, current.attack, current.judgement.reasoning
            )
            if child is None:
                break
            child_result = await self._execute_and_judge(category, child)
            produced.append(child_result)
            await self._persist_and_emit(campaign.id, child_result, on_result)
            current = child_result

        return produced

    async def _execute_and_judge(
        self, category: AttackCategory, prompt: AttackPrompt
    ) -> AttackResult:
        """Send one prompt to the target, then have the judge score it."""
        async with self._sem:
            response = await self._call_target(prompt)
        async with self._sem:
            judgement = await self._judge.judge(
                category, self._cfg.target.system_prompt, prompt, response
            )
        return AttackResult(attack=prompt, response=response, judgement=judgement)

    async def _call_target(self, prompt: AttackPrompt) -> TargetResponse:
        """Dispatch an adversarial prompt to the target LLM.

        Multi-turn escalation prompts encode turns as lines prefixed with
        ``USER:`` / ``ASSISTANT:``; those are parsed into a message list so the
        target sees a genuine multi-turn conversation.
        """
        start = time.perf_counter()
        try:
            messages = _parse_conversation(prompt.prompt)
            resp = await self._client.complete(
                model=self._cfg.target.model,
                system=build_target_prompt(self._cfg.target.system_prompt),
                messages=messages,
                max_tokens=self._cfg.llm.max_tokens,
                temperature=0.0,  # target uses its deployed (deterministic) config
            )
            return TargetResponse(
                attack_id=prompt.id,
                content=resp.text,
                latency_ms=resp.latency_ms,
            )
        except Exception as exc:  # capture, don't crash the campaign
            latency = int((time.perf_counter() - start) * 1000)
            log.warning("Target call failed for attack %s: %s", prompt.id, exc)
            return TargetResponse(
                attack_id=prompt.id, content="", latency_ms=latency, error=str(exc)
            )

    # -- helpers --------------------------------------------------------------
    async def _persist_and_emit(
        self,
        campaign_id: str,
        result: AttackResult,
        on_result: Optional[ResultCallback],
    ) -> None:
        await self._store.save_result(campaign_id, result)
        if on_result is not None:
            # Never let a dashboard callback failure abort the campaign.
            try:
                await on_result(result)
            except Exception:  # pragma: no cover
                log.exception("on_result callback raised; continuing")

    @staticmethod
    def _should_mutate(score: RiskScore, threshold: RiskScore) -> bool:
        """Mutate only attacks scoring at/above the threshold but below critical.

        A critical breach already fully succeeded — no need to mutate further.
        """
        if score is RiskScore.CRITICAL:
            return False
        return SCORE_ORDER[score] >= SCORE_ORDER[threshold]

    # -- reporting passthrough ------------------------------------------------
    async def build_report(
        self, campaign: Campaign, results: list[AttackResult]
    ) -> dict:
        """Build the structured report (delegates to the reporter agent)."""
        return await self._reporter.build(campaign, results)

    def render_markdown(self, report: dict) -> str:
        return self._reporter.render_markdown(report)


def _parse_conversation(prompt_text: str) -> list[dict[str, str]]:
    """Turn a possibly multi-turn prompt string into an API message list.

    Lines beginning with ``USER:`` or ``ASSISTANT:`` start a new turn; text
    without any such markers is treated as a single user message. A trailing
    assistant turn is dropped because the API requires the final turn to be the
    user's.
    """
    if "USER:" not in prompt_text and "ASSISTANT:" not in prompt_text:
        return [{"role": "user", "content": prompt_text}]

    messages: list[dict[str, str]] = []
    role: Optional[str] = None
    buffer: list[str] = []

    def flush() -> None:
        if role and buffer:
            messages.append({"role": role, "content": "\n".join(buffer).strip()})

    for line in prompt_text.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("USER:"):
            flush()
            role, buffer = "user", [stripped[5:].strip()]
        elif stripped.upper().startswith("ASSISTANT:"):
            flush()
            role, buffer = "assistant", [stripped[10:].strip()]
        else:
            buffer.append(line)
    flush()

    # The conversation must start with a user turn and end with one.
    while messages and messages[0]["role"] != "user":
        messages.pop(0)
    while messages and messages[-1]["role"] != "user":
        messages.pop()
    return messages or [{"role": "user", "content": prompt_text}]
