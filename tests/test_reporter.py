"""Unit tests for the deterministic reporter aggregation."""

from __future__ import annotations

import pytest

from redteam.agents.reporter import ReporterAgent
from redteam.config import LLMConfig
from redteam.llm.client import MockClient
from redteam.models import (
    AttackPrompt,
    AttackResult,
    Campaign,
    Judgement,
    RiskScore,
    TargetResponse,
)


def _make_result(category: str, score: RiskScore, breach_type: str) -> AttackResult:
    attack = AttackPrompt(category=category, variant=1, prompt="p")
    response = TargetResponse(attack_id=attack.id, content="r")
    judgement = Judgement(
        attack_id=attack.id,
        response_id=response.id,
        score=score,
        breach_type=breach_type,
        complied=score is RiskScore.CRITICAL,
        leaked_info=False,
        refused_cleanly=score is RiskScore.PASS,
        reasoning="test",
    )
    return AttackResult(attack=attack, response=response, judgement=judgement)


@pytest.mark.asyncio
async def test_aggregation_and_scoring():
    cfg = LLMConfig(provider="mock")
    reporter = ReporterAgent(MockClient(cfg), cfg)
    campaign = Campaign(
        target_name="t", target_model="m", provider="mock",
        categories=["jailbreak", "prompt_leakage"], variants_per_category=2,
    )
    results = [
        _make_result("jailbreak", RiskScore.CRITICAL, "harmful_compliance"),
        _make_result("jailbreak", RiskScore.PASS, "none"),
        _make_result("prompt_leakage", RiskScore.HIGH, "system_prompt_leak"),
        _make_result("prompt_leakage", RiskScore.PASS, "none"),
    ]

    report = await reporter.build(campaign, results)
    summary = report["executive_summary"]

    assert summary["total_attacks"] == 4
    assert summary["total_breaches"] == 2
    assert summary["critical_breaches"] == 1
    assert summary["breach_rate_pct"] == 50.0
    # Safety score should be well below 100 given a critical + high breach.
    assert summary["safety_score"] < 80
    # Both breached categories should be flagged as top risk areas.
    assert set(summary["top_risk_areas"]) == {"jailbreak", "prompt_leakage"}

    # Remediation playbook must include guidance for the observed breach types.
    breach_types = {item["breach_type"] for item in report["remediation_playbook"]}
    assert "system_prompt_leak" in breach_types
    assert "harmful_compliance" in breach_types


@pytest.mark.asyncio
async def test_perfect_run_scores_100():
    cfg = LLMConfig(provider="mock")
    reporter = ReporterAgent(MockClient(cfg), cfg)
    campaign = Campaign(
        target_name="t", target_model="m", provider="mock",
        categories=["jailbreak"], variants_per_category=2,
    )
    results = [_make_result("jailbreak", RiskScore.PASS, "none") for _ in range(3)]
    report = await reporter.build(campaign, results)
    assert report["executive_summary"]["safety_score"] == 100
    assert report["executive_summary"]["total_breaches"] == 0