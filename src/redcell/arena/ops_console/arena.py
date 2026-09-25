"""工单台靶场作为一个可注册的整体。"""

from __future__ import annotations

from pathlib import Path

from redcell.arena.benign import BENIGN_TASK_EVALUATOR_VERSION
from redcell.arena.definition import ArenaDefinition
from redcell.arena.ops_console.benign import BENIGN_TASKS
from redcell.arena.ops_console.cases import POSITIVE_CASES
from redcell.arena.ops_console.policy import OPS_CONSOLE_POLICY, TARGET_NAME
from redcell.arena.ops_console.prompts import DEFENCE_BLOCKS, build_base_role
from redcell.arena.ops_console.tools import OpsConsoleTools

OPS_CONSOLE_ARENA_VERSION = "ops-console/2026-09-24.1"
"""靶场内容版本。policy、提示、工具、数据任一变动都要升。"""

OPS_CONSOLE_GOLDEN_FIXTURE_DIGEST = (
    "32eb0c2a5e891387b94c73a516e2fe4a7c72dadf2522ac6480335c41e9f35c68"
)
"""本靶场 golden 集的冻结摘要;由测试钉住,改 fixture 必须同步改这里。"""

OPS_CONSOLE_GOLDEN_FIXTURE_IDS = frozenset(
    {
        "positive-canary-full",
        "positive-role-escalation-blocked",
        "positive-role-escalation-realized",
        "positive-forbidden-export-blocked",
        "positive-unknown-tool-realized",
        "positive-refund-over-limit",
        "positive-confirmation-bypass",
        "positive-partial-observability",
        "positive-constraint-precedence",
        "positive-both-channels",
        "negative-refusal",
        "negative-canary-prefix",
        "negative-prompt-fingerprint",
        "negative-attacker-supplied-canary",
        "negative-harmless-kb",
        "negative-own-ticket",
        "negative-first-confirmable-call",
        "negative-confirmed-across-turns",
        "negative-plain-response",
        "negative-own-queue",
        "negative-repeat-after-confirmed-execute",
    }
)

OPS_CONSOLE_ARENA = ArenaDefinition(
    id=TARGET_NAME,
    version=OPS_CONSOLE_ARENA_VERSION,
    policy=OPS_CONSOLE_POLICY,
    default_actor="agent_l1",
    defense_blocks=DEFENCE_BLOCKS,
    base_role_builder=build_base_role,
    tools_factory=OpsConsoleTools,
    positive_cases=tuple(POSITIVE_CASES),
    benign_tasks=tuple(BENIGN_TASKS),
    benign_task_evaluator_version=BENIGN_TASK_EVALUATOR_VERSION,
    golden_fixture=Path("tests/fixtures/level1-golden-ops-console-v2.json"),
    golden_fixture_digest=OPS_CONSOLE_GOLDEN_FIXTURE_DIGEST,
    golden_fixture_ids=OPS_CONSOLE_GOLDEN_FIXTURE_IDS,
)
