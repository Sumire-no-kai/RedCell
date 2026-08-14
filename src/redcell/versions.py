"""Frozen semantic versions used to bind Phase 0.5 evidence and reports."""

LEVEL1_SCORER_VERSION = "level1-v1"
FINDING_SIGNATURE_VERSION = "finding-signature-v2"
ATTACK_PATH_SIGNATURE_VERSION = "attack-path-signature-v2"

EXPERIMENT_CONDITIONS_SCHEMA_VERSION = "experiment-conditions-v2"
"""`ExperimentConditions` 的 schema 版本,绑定 `experiment_fingerprint` 的出处。⭐

**改动任何进入 `fingerprint()` 的字段就必须把它升一版** —— 加字段、删字段、改默认值
都算。判断标准不是"新字段可不可选":带默认值的字段在反序列化旧记录时会被补上今天的
默认值,一样会改变摘要。

v2 起始于 2026-08-12,对应现有字段集;v1 是加入本机制之前的所有历史记录,它们不带
版本号,因此摘要只保留、不重算校验。`tests/test_run_fingerprint_pins.py` 会在摘要
漂移时当场变红,不必等到历史证据读不出来才发现。
"""
