"""Judge agent — scores a target response against the safety rubric.

The judge runs as a separate LLM instance with its own system prompt to reduce
bias (it is not told to *want* the attack to succeed). It is prompted to return
strict JSON, which this module validates into a :class:`Judgement`.
"""

from __future__ import annotations

import logging

from ..categories import AttackCategory
from ..config import LLMConfig
from ..llm.client import LLMClient
from ..llm.prompts import build_judge_prompt
from ..models import AttackPrompt, Judgement, RiskScore, TargetResponse
from ._parsing import parse_json_object

log = logging.getLogger(__name__)


class JudgeAgent:
    """Evaluates target responses and assigns a risk score."""

    def __init__(self, client: LLMClient, cfg: LLMConfig) -> None:
        self._client = client
        self._cfg = cfg

    async def judge(
        self,
        category: AttackCategory,
        target_system_prompt: str,
        attack: AttackPrompt,
        response: TargetResponse,
    ) -> Judgement:
        """Return a structured verdict for one attack/response pair.

        If the target call itself errored, we short-circuit to a ``pass`` with an
        explanatory breach_type rather than asking the judge to evaluate an
        empty response.
        """
        if response.error:
            return Judgement(
                attack_id=attack.id,
                response_id=response.id,
                score=RiskScore.PASS,
                breach_type="target_error",
                complied=False,
                leaked_info=False,
                refused_cleanly=True,
                reasoning=f"Target call failed: {response.error}",
            )

        system, user = build_judge_prompt(
            category, target_system_prompt, attack.prompt, response.content
        )
        resp = await self._client.complete(
            model=self._cfg.judge_model,
            system=system,
            messages=[{"role": "user", "content": user}],
            max_tokens=self._cfg.max_tokens,
            # Judge should be deterministic/consistent, not creative.
            temperature=0.0,
        )

        return self._parse(resp.text, attack, response)

    def _parse(
        self, text: str, attack: AttackPrompt, response: TargetResponse
    ) -> Judgement:
        """Validate the judge's JSON into a Judgement (with safe fallbacks)."""
        try:
            data = parse_json_object(text)
        except ValueError:
            log.warning("Judge output unparseable for attack %s; defaulting to medium", attack.id)
            # Unparseable judge output is itself a signal something odd happened;
            # score conservatively as 'medium' so it surfaces for human review.
            return Judgement(
                attack_id=attack.id,
                response_id=response.id,
                score=RiskScore.MEDIUM,
                breach_type="unparseable_judgement",
                complied=False,
                leaked_info=False,
                refused_cleanly=False,
                reasoning="Judge did not return valid JSON; flagged for manual review.",
            )

        # Coerce the score string to the enum, defaulting to 'medium' if unknown.
        raw_score = str(data.get("score", "medium")).strip().lower()
        try:
            score = RiskScore(raw_score)
        except ValueError:
            score = RiskScore.MEDIUM

        return Judgement(
            attack_id=attack.id,
            response_id=response.id,
            score=score,
            breach_type=str(data.get("breach_type", "unspecified")),
            complied=bool(data.get("complied", False)),
            leaked_info=bool(data.get("leaked_info", False)),
            refused_cleanly=bool(data.get("refused_cleanly", False)),
            reasoning=str(data.get("reasoning", "")),
        )