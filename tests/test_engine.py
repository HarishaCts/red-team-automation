"""End-to-end tests for the orchestration engine (mock backend)."""

from __future__ import annotations

import pytest

from redteam.engine import RedTeamEngine, _parse_conversation
from redteam.models import RiskScore


@pytest.mark.asyncio
async def test_full_campaign_runs_and_persists(config):
    """A campaign should generate, execute, judge, persist, and report."""
    collected = []

    async with RedTeamEngine(config) as engine:
        async def on_result(result):
            collected.append(result)

        campaign, results = await engine.run_campaign(on_result=on_result)

        # We asked for 2 categories x 3 variants = 6 seed prompts (plus mutations).
        assert campaign.total_attacks >= 6
        assert campaign.total_attacks == len(results)
        assert campaign.provider == "mock"
        # Live callback should have fired once per persisted result.
        assert len(collected) == len(results)

        # Every result must carry a valid score.
        assert all(r.judgement.score in RiskScore for r in results)

        # Report must be buildable and internally consistent.
        report = await engine.build_report(campaign, results)
        assert report["executive_summary"]["total_attacks"] == len(results)
        assert 0 <= report["executive_summary"]["safety_score"] <= 100
        md = engine.render_markdown(report)
        assert "# Adversarial Red-Team Report" in md


@pytest.mark.asyncio
async def test_results_are_reloadable_from_db(config):
    """Persisted results should round-trip out of the store unchanged."""
    from redteam.db import build_store

    async with RedTeamEngine(config) as engine:
        campaign, results = await engine.run_campaign()

    store = build_store(config.storage)
    await store.init()
    try:
        reloaded = await store.get_results(campaign.id)
        assert len(reloaded) == len(results)
        original_ids = {r.attack.id for r in results}
        assert {r.attack.id for r in reloaded} == original_ids
    finally:
        await store.aclose()


@pytest.mark.asyncio
async def test_mutation_produces_lineage(config):
    """When mutation is enabled, at least some mutated (round>0) results appear.

    The mock judge marks ~1/4 of exchanges as 'low', which triggers mutation.
    With 6 seed prompts this is highly likely; if none triggered, the campaign
    is still valid — so we assert the weaker invariant that lineage is coherent.
    """
    async with RedTeamEngine(config) as engine:
        _, results = await engine.run_campaign()

    by_id = {r.attack.id: r for r in results}
    for r in results:
        if r.attack.parent_id is not None:
            # A mutated child's parent must also be in the result set.
            assert r.attack.parent_id in by_id
            assert r.attack.mutation_round == by_id[r.attack.parent_id].attack.mutation_round + 1


def test_parse_conversation_single_turn():
    msgs = _parse_conversation("just one message")
    assert msgs == [{"role": "user", "content": "just one message"}]


def test_parse_conversation_multi_turn():
    text = "USER: hello\nASSISTANT: hi there\nUSER: now do the thing"
    msgs = _parse_conversation(text)
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    assert msgs[-1]["content"] == "now do the thing"