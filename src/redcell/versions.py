"""Frozen semantic versions used to bind Phase 0.5 evidence and reports."""

LEVEL1_SCORER_VERSION = "level1-v1"
FINDING_SIGNATURE_VERSION = "finding-signature-v2"
ATTACK_PATH_SIGNATURE_VERSION = "attack-path-signature-v2"

EXPERIMENT_CONDITIONS_SCHEMA_VERSION = "experiment-conditions-v4"
HOST_BOUND_EXPERIMENT_CONDITIONS_SCHEMA_VERSION = "experiment-conditions-v3"
FEEDBACK_EXPERIMENT_CONDITIONS_SCHEMA_VERSION = "experiment-conditions-v5"
SUPPORTED_EXPERIMENT_CONDITIONS_SCHEMA_VERSIONS = frozenset(
    {
        HOST_BOUND_EXPERIMENT_CONDITIONS_SCHEMA_VERSION,
        EXPERIMENT_CONDITIONS_SCHEMA_VERSION,
        FEEDBACK_EXPERIMENT_CONDITIONS_SCHEMA_VERSION,
    }
)
"""`ExperimentConditions` 的 schema 版本,绑定 `experiment_fingerprint` 的出处。⭐

**改动任何进入 `fingerprint()` 的字段就必须把它升一版** —— 加字段、删字段、改默认值
都算。判断标准不是"新字段可不可选":带默认值的字段在反序列化旧记录时会被补上今天的
默认值,一样会改变摘要。

v2 于 2026-08-14 随本机制首次落盘。v3 于 2026-08-20 增加实际 HTTP 超时和 Windows
唤醒锁宿主档案；v4 增加显式 tool-call protocol 身份；v5 为反馈驱动 Run 冻结攻击驱动器、
观察权限与停止策略。v3/v4 继续可重算验证，旧记录缺失的新字段保持 `None` 且不进入摘要。
`tests/test_run_fingerprint_pins.py`
会在摘要漂移时当场变红,不必等到历史证据读不出来才发现。

**例外(#60 起的做法):未设置时不进入序列化结果的可选字段不升版。** 旧记录里没有它,
重算摘要时也不会被补上;新记录里出现它,本身就说明产自加入该字段之后的代码。
`max_tokens_parameter`、`reasoning_effort`、`arena_id` / `arena_version` 都属于这一类,
钉扎测试同时锁住"未设置时逐字节不变"与"设置后进入摘要"。
"""
