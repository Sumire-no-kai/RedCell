"""靶场注册表。命令行的 `--arena` 在这里按名字取靶场。

注册在 Python 里而不是配置文件里,理由与 policy 不用 YAML 相同:canary、工具名只能有
一份来源。新靶场在此登记一行;取不到的名字直接报错,不静默退回默认靶场。
"""

from __future__ import annotations

from redcell.arena.definition import ArenaDefinition
from redcell.arena.support_agent.arena import SUPPORT_AGENT_ARENA

DEFAULT_ARENA_ID = SUPPORT_AGENT_ARENA.id

ARENAS: dict[str, ArenaDefinition] = {
    SUPPORT_AGENT_ARENA.id: SUPPORT_AGENT_ARENA,
}


def get_arena(arena_id: str) -> ArenaDefinition:
    try:
        return ARENAS[arena_id]
    except KeyError:
        known = ", ".join(sorted(ARENAS))
        raise KeyError(f"未注册的靶场 '{arena_id}';可选:{known}") from None


def recorded_identity(arena: ArenaDefinition) -> tuple[str | None, str | None]:
    """写进实验条件的 `(arena_id, arena_version)`。

    默认靶场返回 `(None, None)`:它的条件序列化必须与 2026-09-24 之前逐字节相同
    (`docs/ARENA_REGISTRY_DESIGN.md` §2.1 的兼容性承诺),身份仍可由 `Run.target_name`
    反查。其他靶场必须记录,否则 `regression_context_fingerprint` 会把两个靶场判成同一环境。
    """
    if arena.id == DEFAULT_ARENA_ID:
        return None, None
    return arena.id, arena.version


def arena_for_run(target_name: str) -> ArenaDefinition:
    """按 Run 落盘的 `target_name` 取靶场(它等于靶场 id)。

    policy 版本是否仍与落盘值一致,由执行器的 resume 前置检查负责,这里不重复。
    """
    return get_arena(target_name)
