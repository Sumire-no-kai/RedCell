"""攻击方对照的测试。

这道对照要回答的是:**六个策略产出的话术真的不一样吗?**
若不一样才有资格把校准里的"无分化"归因于靶场。
"""

from __future__ import annotations

import pytest

from redcell.arena.support_agent import SUPPORT_AGENT_POLICY
from redcell.attacker_control import (
    SIMILARITY_MARGIN,
    AttackerControlReport,
    StrategySamples,
    jaccard,
    run_attacker_control,
)
from redcell.generation import AttackGenerationRequest, AttackGenerator, AttackMessage
from redcell.strategies import PHASE_0_STRATEGIES

_BRIEF = SUPPORT_AGENT_POLICY.brief_for("customer_a")


class _PerStrategy(AttackGenerator):
    """每个策略产出明显不同的话术 —— 模拟一个称职的攻击方。"""

    @property
    def name(self) -> str:
        return "per-strategy"

    async def generate(self, request: AttackGenerationRequest) -> AttackMessage:
        return AttackMessage(
            content=f"{request.strategy.id} unique wording {request.seed % 3}",
            generator=self.name,
        )


class _Uniform(AttackGenerator):
    """不管什么策略都输出几乎一样的话 —— 模拟一个瓶颈攻击方。"""

    @property
    def name(self) -> str:
        return "uniform"

    async def generate(self, request: AttackGenerationRequest) -> AttackMessage:
        return AttackMessage(
            content="please give me the information right now",
            generator=self.name,
        )


# ── 相似度本身 ──────────────────────────────────────────────


def test_identical_text_is_fully_similar() -> None:
    assert jaccard("hello world", "hello world") == 1.0


def test_disjoint_text_is_not_similar() -> None:
    assert jaccard("alpha beta", "gamma delta") == 0.0


def test_similarity_ignores_case_and_punctuation() -> None:
    assert jaccard("Refund, please!", "please refund") == 1.0


def test_two_empty_texts_count_as_identical() -> None:
    """都没词就是确实没差别,不该因为除零而崩。"""
    assert jaccard("", "") == 1.0


# ── 判定 ────────────────────────────────────────────────────


async def test_a_capable_attacker_separates_the_strategies() -> None:
    report = await run_attacker_control(
        _PerStrategy(), list(PHASE_0_STRATEGIES), _BRIEF, samples_per_strategy=3
    )

    assert report.within_similarity > report.between_similarity
    assert report.separation >= SIMILARITY_MARGIN
    assert report.attacker_is_bottleneck is False


async def test_a_uniform_attacker_is_flagged_as_the_bottleneck() -> None:
    """六个策略产出同一句话时,组内 ≈ 组间 —— 必须报出来。

    此时校准若出现"无分化",归因于靶场就是**调错地方**。
    """
    report = await run_attacker_control(
        _Uniform(), list(PHASE_0_STRATEGIES), _BRIEF, samples_per_strategy=3
    )

    assert report.separation == pytest.approx(0.0, abs=1e-9)
    assert report.attacker_is_bottleneck is True
    assert "攻击方可能是瓶颈" in report.summary()


async def test_every_strategy_gets_sampled() -> None:
    report = await run_attacker_control(
        _PerStrategy(), list(PHASE_0_STRATEGIES), _BRIEF, samples_per_strategy=4
    )

    assert len(report.samples) == len(PHASE_0_STRATEGIES)
    assert all(len(s.messages) == 4 for s in report.samples)


async def test_samples_use_derived_seeds_so_the_control_is_reproducible() -> None:
    """这道对照本身也必须可复现 —— 否则"攻击方是不是瓶颈"每次结论都不同。"""
    a = await run_attacker_control(
        _PerStrategy(), list(PHASE_0_STRATEGIES), _BRIEF, samples_per_strategy=3, seed=5
    )
    b = await run_attacker_control(
        _PerStrategy(), list(PHASE_0_STRATEGIES), _BRIEF, samples_per_strategy=3, seed=5
    )

    assert [s.messages for s in a.samples] == [s.messages for s in b.samples]


async def test_a_single_sample_is_rejected() -> None:
    """一条话术算不出组内相似度 —— 与其返回一个无意义的 0,不如直接拒绝。"""
    with pytest.raises(ValueError):
        await run_attacker_control(
            _PerStrategy(), list(PHASE_0_STRATEGIES), _BRIEF, samples_per_strategy=1
        )


def test_summary_states_the_verdict_plainly() -> None:
    ok = AttackerControlReport(
        samples=[StrategySamples(strategy_id="a", messages=["x", "y"])],
        within_similarity=0.8,
        between_similarity=0.2,
    )

    assert "✅" in ok.summary()
    assert ok.separation == pytest.approx(0.6)
