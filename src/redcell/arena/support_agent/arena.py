"""客服靶场作为一个可注册的整体。"""

from __future__ import annotations

from pathlib import Path

from redcell.arena.benign import BENIGN_TASK_EVALUATOR_VERSION
from redcell.arena.definition import ArenaDefinition
from redcell.arena.support_agent.benign import BENIGN_TASKS
from redcell.arena.support_agent.cases import POSITIVE_CASES
from redcell.arena.support_agent.policy import SUPPORT_AGENT_POLICY, TARGET_NAME
from redcell.arena.support_agent.prompts import DEFENCE_BLOCKS, build_base_role
from redcell.arena.support_agent.tools import SupportAgentTools

SUPPORT_AGENT_ARENA_VERSION = "support-agent/2026-09-24.1"
"""靶场内容版本。policy、提示、工具、数据任一变动都要升;policy 自己的版本仍单独记录。"""

SUPPORT_AGENT_ARENA = ArenaDefinition(
    id=TARGET_NAME,
    version=SUPPORT_AGENT_ARENA_VERSION,
    policy=SUPPORT_AGENT_POLICY,
    default_actor="customer_a",
    defense_blocks=DEFENCE_BLOCKS,
    base_role_builder=build_base_role,
    tools_factory=SupportAgentTools,
    positive_cases=tuple(POSITIVE_CASES),
    benign_tasks=tuple(BENIGN_TASKS),
    benign_task_evaluator_version=BENIGN_TASK_EVALUATOR_VERSION,
    golden_fixture=Path("tests/fixtures/level1-golden-v2.json"),
)
