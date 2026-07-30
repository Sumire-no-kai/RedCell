"""稳定、分域的随机种子派生。

一个全局 RNG 像所有模块共用一只号码桶:任意模块多抽一次,后面全部结果都会改变。
这里从 Run 主种子为 Controller 和每场 Attempt 派生互不干扰的子种子。
"""

from __future__ import annotations

import hashlib
import json
from typing import TypeAlias

from pydantic import Field

from redcell.protocols.common import RedCellModel

SeedPart: TypeAlias = str | int
MAX_SIGNED_64_BIT = (1 << 63) - 1


def derive_seed(root_seed: int, *parts: SeedPart) -> int:
    """用稳定算法派生一个 SQLite/Python 都安全的非负 63-bit 种子。

    禁止使用 Python `hash()`:它的字符串哈希默认带进程级随机盐,
    相同输入在另一个进程里可能得到不同结果。
    """
    payload = json.dumps(
        [root_seed, *parts],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.blake2b(
        payload,
        digest_size=8,
        person=b"RedCellSeedV1",
    ).digest()
    return int.from_bytes(digest, "big") & MAX_SIGNED_64_BIT


class AttemptSeeds(RedCellModel):
    """一场 Attempt 使用的全部随机域。"""

    run_seed: int = Field(ge=0)
    controller_seed: int = Field(ge=0)
    attempt_seed: int = Field(ge=0)
    generator_seed: int = Field(ge=0)
    actor_seed: int = Field(ge=0)
    target_seed: int = Field(ge=0)


def controller_seed_for(run_seed: int) -> int:
    return derive_seed(run_seed, "controller")


def seeds_for_attempt(run_seed: int, attempt_index: int) -> AttemptSeeds:
    if attempt_index < 0:
        raise ValueError("attempt_index 必须 >= 0")

    attempt_seed = derive_seed(run_seed, "attempt", attempt_index)
    return AttemptSeeds(
        run_seed=run_seed,
        controller_seed=controller_seed_for(run_seed),
        attempt_seed=attempt_seed,
        generator_seed=derive_seed(attempt_seed, "generator"),
        actor_seed=derive_seed(attempt_seed, "actor"),
        target_seed=derive_seed(attempt_seed, "target"),
    )
