"""模型指纹探针的测试。

指纹是"厂商静默换模型"的唯一探测手段,所以它自己的行为必须先钉死 ——
一个会误报或漏报的探针,比没有探针更糟:你会依赖它。
"""

from __future__ import annotations

from redcell.llm import (
    PROBE_SET_VERSION,
    PROBES,
    ModelFingerprint,
    ScriptedProvider,
    digest_of,
    take_fingerprint,
)


def _provider(replies: list[str], *, model: str = "glm-4.7-flash") -> ScriptedProvider:
    return ScriptedProvider(replies, model=model)


# ── 摘要本身 ────────────────────────────────────────────────


def test_digest_is_stable_across_calls() -> None:
    assert digest_of(["a", "b"]) == digest_of(["a", "b"])


def test_digest_changes_when_any_reply_changes() -> None:
    assert digest_of(["a", "b"]) != digest_of(["a", "c"])


def test_digest_is_order_sensitive() -> None:
    """探测集有固定顺序,乱序应当算作不同——否则回复错位也检测不到。"""
    assert digest_of(["a", "b"]) != digest_of(["b", "a"])


def test_digest_separator_cannot_be_forged_by_newlines() -> None:
    """用 \\x00 而非换行分隔:回复本身可能含换行。

    若用换行分隔,`["a\\nb"]` 与 `["a", "b"]` 会折叠成同一个摘要 ——
    那意味着两个不同的模型行为拿到同一个指纹,是漏报。
    """
    assert digest_of(["a\nb"]) != digest_of(["a", "b"])


def test_digest_is_not_python_hash() -> None:
    """必须是跨进程稳定的十六进制摘要,不能是带随机盐的 hash()。"""
    value = digest_of(["a"])
    assert len(value) == 32
    int(value, 16)  # 不是合法十六进制就会抛异常


# ── 采样 ────────────────────────────────────────────────────


async def test_fingerprint_issues_one_call_per_probe() -> None:
    """每条探测单独一次调用:合并成多轮会让前一条的抖动传染后一条。"""
    provider = _provider([f"reply-{i}" for i in range(len(PROBES))])

    await take_fingerprint(provider)

    assert provider.call_count == len(PROBES)


async def test_fingerprint_probes_at_temperature_zero() -> None:
    """与靶场相反:这里要的是稳定信号,随机性是噪声。

    (靶场按 CALIBRATION §3 必须用 0.7 —— 同一个参数,目的相反,取值相反。)
    """
    seen: list[float] = []

    class Recording(ScriptedProvider):
        async def complete(self, messages, *, model=None, temperature=0.0, max_tokens=None):
            seen.append(temperature)
            return await super().complete(
                messages, model=model, temperature=temperature, max_tokens=max_tokens
            )

    await take_fingerprint(Recording(["x"] * len(PROBES)))

    assert seen == [0.0] * len(PROBES)


async def test_fingerprint_records_both_model_strings() -> None:
    """请求串与回传串分别留档——实测两家只会原样回显,但那本身就是要记录的事实。"""
    fp = await take_fingerprint(_provider(["x"] * len(PROBES), model="glm-4.7-flash"))

    assert fp.requested_model == "glm-4.7-flash"
    assert fp.reported_model == "glm-4.7-flash"
    assert fp.provider == "scripted"
    assert fp.probe_set_version == PROBE_SET_VERSION


async def test_same_replies_produce_the_same_fingerprint() -> None:
    a = await take_fingerprint(_provider(["p", "q", "r", "s"] * 2), samples=2)
    b = await take_fingerprint(_provider(["p", "q", "r", "s"] * 2), samples=2)

    assert a.stable is True
    assert a.matches(b)


async def test_changed_replies_break_the_match() -> None:
    """指纹变了是**强证据**:模型行为确实变了,两轮数据不该合在一起比。"""
    a = await take_fingerprint(_provider(["p", "q", "r", "s"] * 2), samples=2)
    b = await take_fingerprint(_provider(["p", "q", "r", "DIFFERENT"] * 2), samples=2)

    assert not a.matches(b)


async def test_replies_are_stripped_before_hashing() -> None:
    """两侧空白不该算作模型变化——那通常只是格式抖动。"""
    a = await take_fingerprint(_provider(["p", "q", "r", "s"] * 2), samples=2)
    b = await take_fingerprint(_provider(["  p  ", "q\n", "\tr", "s "] * 2), samples=2)

    assert a.matches(b)


# ── 稳定性自检(能力声明)────────────────────────────────────


async def test_single_sample_leaves_stability_unknown() -> None:
    """只采一遍无从判断稳定性,保守起见不足以支撑"没漂移"的结论。"""
    fp = await take_fingerprint(_provider(["p", "q", "r", "s"]))

    assert fp.samples == 1
    assert fp.stable is None
    assert fp.usable_for_drift_detection is False


async def test_unstable_provider_is_detected_and_declared() -> None:
    """实测 Gemini 属于此类:同一模型连采两次,摘要不同。

    此时必须明确声明"该 provider 上无法做漂移检测",
    而不是给出一个看起来能用、实则天天误报的结果。
    """
    provider = _provider(["p", "q", "r", "s", "p", "q", "r", "变了"])
    fp = await take_fingerprint(provider, samples=2)

    assert fp.stable is False
    assert fp.usable_for_drift_detection is False


async def test_unstable_fingerprints_never_match_even_when_digests_agree() -> None:
    """摘要相等也可能只是碰巧——不稳定的指纹不构成"没漂移"的证据。"""
    a = ModelFingerprint(
        provider="gemini",
        requested_model="m",
        reported_model="m",
        probe_set_version=PROBE_SET_VERSION,
        digest="相同的摘要",
        samples=2,
        stable=False,
    )
    b = a.model_copy()

    assert a.digest == b.digest
    assert not a.matches(b)


async def test_samples_multiplies_the_call_count() -> None:
    """采样成本要可预期:免费层很紧,4 条探测 × N 遍必须心里有数。"""
    provider = _provider(["x"] * (len(PROBES) * 3))
    await take_fingerprint(provider, samples=3)

    assert provider.call_count == len(PROBES) * 3


# ── 版本不可比 ──────────────────────────────────────────────


def test_different_probe_set_versions_never_match() -> None:
    """换了题目的两个哈希摆在一起,比没有哈希更容易得出错误结论。

    所以判为不可比,而不是碰巧 digest 相同就说"没变"。
    (两侧都标 stable=True,确保这里测的是版本闸而不是稳定性闸。)
    """
    base = {
        "provider": "glm",
        "requested_model": "m",
        "reported_model": "m",
        "digest": "同一个摘要",
        "samples": 2,
        "stable": True,
    }
    old = ModelFingerprint(**base, probe_set_version=1)
    new = ModelFingerprint(**base, probe_set_version=2)

    assert old.matches(old)  # 同版本自比应当成立,否则下面的断言说明不了问题
    assert not old.matches(new)


def test_renamed_model_breaks_the_match_even_if_digest_holds() -> None:
    """回传串与摘要是两个独立信号,任一变化都值得停下来看一眼。"""
    base = {
        "provider": "glm",
        "requested_model": "m",
        "digest": "d",
        "probe_set_version": 1,
        "samples": 2,
        "stable": True,
    }
    a = ModelFingerprint(**base, reported_model="glm-4.7-flash")
    b = ModelFingerprint(**base, reported_model="glm-4.7-flash-0301")

    assert a.matches(a)
    assert not a.matches(b)


def test_summary_is_one_line_and_carries_every_signal() -> None:
    """DEVLOG 要抄的就是这一行,少一个字段就得回去翻代码。"""
    fp = ModelFingerprint(
        provider="glm",
        requested_model="glm-4.7-flash",
        reported_model="glm-4.7-flash",
        probe_set_version=1,
        digest="abc123",
        samples=2,
        stable=True,
    )
    line = fp.summary()

    assert "\n" not in line
    assert "glm-4.7-flash" in line
    assert "v1" in line
    assert "abc123" in line
    assert "稳定" in line


def test_summary_flags_an_unusable_fingerprint() -> None:
    """不稳定必须在那一行里看得见——否则抄进 DEVLOG 的就是个误导性的哈希。"""
    fp = ModelFingerprint(
        provider="gemini",
        requested_model="gemini-3.6-flash",
        reported_model="gemini-3.6-flash",
        probe_set_version=1,
        digest="abc123",
        samples=2,
        stable=False,
    )

    assert "不可用于漂移检测" in fp.summary()
