"""只读、脱敏的逐轮对话直播。

正式矩阵的 child stdout 会写入逐格日志，不能把逐轮文本直接 ``print`` 到
``redcell run`` 再期待父 runner 能看见。这里改为读取已经提交到 SQLite 的
``TURN_COMPLETED`` 事件：它不向执行器发送输入、不创建表、不改写任何 run 证据。

直播只用于确认作业仍在推进。它刻意不输出工具调用、检测分数、Finding 或 canary
明文；原始 trace 仍只保存在受保护的本地实验库中。
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.engine import make_url

from redcell.arena.support_agent import SUPPORT_AGENT_POLICY
from redcell.executor import TurnCheckpoint
from redcell.protocols.policy import Policy
from redcell.protocols.run import RunEvent, RunEventType

REDACTED_TEXT = "[已脱敏]"


def _stdout(message: str) -> None:
    print(message, flush=True)


@dataclass(frozen=True)
class LiveConversation:
    """一条已完整执行、已完成评分、可安全直播的对话回合。"""

    run_id: str
    attempt_id: str
    turn_index: int
    attacker_message: str
    target_message: str


@dataclass(frozen=True)
class _StoredEvent:
    row_id: int
    event: RunEvent | None


def conversation_from_event(event: RunEvent, *, policy: Policy) -> LiveConversation | None:
    """从一个已持久化事件投影出仅含双方文本的直播记录。

    ``TURN_COMPLETED`` 是在 target 返回且 Level-1 scorer 完成后才写入的，因而不会
    直播半截回复或尚未提交的请求。损坏/旧形状事件不应影响正式作业，故仅跳过它们。
    """
    if event.event_type is not RunEventType.TURN_COMPLETED:
        return None
    try:
        checkpoint = TurnCheckpoint.model_validate(event.payload["checkpoint"])
    except (KeyError, TypeError, ValueError):
        return None

    return LiveConversation(
        run_id=checkpoint.run_id,
        attempt_id=checkpoint.attempt_id,
        turn_index=checkpoint.turn.index,
        attacker_message=_redact_for_terminal(checkpoint.turn.attacker_message, policy),
        target_message=_redact_for_terminal(checkpoint.turn.output.assistant_message, policy),
    )


def format_conversation(conversation: LiveConversation) -> str:
    """渲染最少的回合标识与双方文本，不附带安全判定或工具细节。"""
    return "\n".join(
        [
            (
                f"[对话 · run {conversation.run_id[:8]} · "
                f"attempt {conversation.attempt_id[:8]} · round {conversation.turn_index + 1}]"
            ),
            _speaker_block("Gemini", conversation.attacker_message),
            _speaker_block("靶场", conversation.target_message),
        ]
    )


class LiveConversationFollower:
    """轮询 SQLite 的只读 tailer；可供 CLI 或 matrix runner 复用。"""

    def __init__(
        self,
        database_url: str,
        *,
        policy: Policy = SUPPORT_AGENT_POLICY,
        emit: Callable[[str], None] = _stdout,
        poll_seconds: float = 1.0,
    ) -> None:
        if poll_seconds <= 0:
            raise ValueError("poll_seconds 必须大于 0")
        self._database_path = _sqlite_database_path(database_url)
        self._policy = policy
        self._emit = emit
        self._poll_seconds = poll_seconds
        self._last_row_id = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def capture_existing(self) -> None:
        """把启动直播前的历史事件标为已见，避免重放旧对话。"""
        self._last_row_id = _latest_row_id(self._database_path)

    def poll_once(self) -> int:
        """输出新完成的回合数。SQLite 尚未创建或短暂忙碌时静默下次再试。"""
        emitted = 0
        for stored_event in _read_events_after(self._database_path, self._last_row_id):
            self._last_row_id = stored_event.row_id
            if stored_event.event is None:
                continue
            conversation = conversation_from_event(stored_event.event, policy=self._policy)
            if conversation is None:
                continue
            self._emit(format_conversation(conversation))
            emitted += 1
        return emitted

    def start(self) -> None:
        """从现在开始后台跟随；调用方必须在退出前调用 ``stop``。"""
        if self._thread is not None:
            raise RuntimeError("live conversation follower 已经启动")
        self.capture_existing()
        self._thread = threading.Thread(
            target=self._follow,
            name="redcell-live-conversations",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """停止 tailer 并做最后一次只读扫描，避免漏掉刚提交的回合。"""
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join()
        self._thread = None
        self.poll_once()

    def _follow(self) -> None:
        while not self._stop.wait(self._poll_seconds):
            self.poll_once()


def _sqlite_database_path(database_url: str) -> Path:
    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or url.database in {None, "", ":memory:"}:
        raise ValueError("逐轮直播仅支持文件型 SQLite 数据库")
    return Path(url.database)


def _latest_row_id(database_path: Path) -> int:
    if not database_path.exists():
        return 0
    try:
        connection = sqlite3.connect(
            f"{database_path.resolve().as_uri()}?mode=ro",
            uri=True,
            timeout=0.25,
        )
    except sqlite3.Error:
        return 0

    try:
        connection.execute("PRAGMA query_only=ON")
        row = connection.execute("SELECT COALESCE(MAX(rowid), 0) FROM run_events").fetchone()
        return int(row[0]) if row is not None else 0
    except (TypeError, ValueError, sqlite3.Error):
        return 0
    finally:
        connection.close()


def _read_events_after(database_path: Path, row_id: int) -> list[_StoredEvent]:
    """以 SQLite ``mode=ro`` 读取事件；绝不借观察器创建或修改数据库。"""
    if not database_path.exists():
        return []
    try:
        connection = sqlite3.connect(
            f"{database_path.resolve().as_uri()}?mode=ro",
            uri=True,
            timeout=0.25,
        )
    except sqlite3.Error:
        return []

    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute(
            """
            SELECT rowid AS row_id, id, run_id, event_type, attempt_id,
                   sequence, payload, created_at
            FROM run_events
            WHERE rowid > ?
            ORDER BY rowid
            """,
            (row_id,),
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        connection.close()

    events: list[_StoredEvent] = []
    for row in rows:
        event: RunEvent | None = None
        try:
            serialized_event = row["payload"]
            if isinstance(serialized_event, str):
                serialized_event = json.loads(serialized_event)
            # RunStore 的 JSON payload 是完整 RunEvent，不是 event.payload 的内层字典。
            # 兼容手工/旧库只写内层 payload 的情况，避免观察器反过来依赖存储实现细节。
            if isinstance(serialized_event, dict) and "event_type" in serialized_event:
                event = RunEvent.model_validate(serialized_event)
            else:
                event = RunEvent.model_validate(
                    {
                        "id": row["id"],
                        "run_id": row["run_id"],
                        "event_type": row["event_type"],
                        "attempt_id": row["attempt_id"],
                        "sequence": row["sequence"],
                        "payload": serialized_event,
                        "created_at": row["created_at"],
                    }
                )
        except (TypeError, ValueError, json.JSONDecodeError):
            # 观察器不能让一条历史损坏记录中断正式 child；该记录仍留在原库供审计。
            pass
        # 即使该行损坏，也推进 cursor，避免同一历史行在每个 poll 周期反复解析。
        events.append(_StoredEvent(row_id=int(row["row_id"]), event=event))
    return events


def _redact_for_terminal(text: str, policy: Policy) -> str:
    protected = [*policy.canary_values(), *policy.canary_prefixes()]
    redacted = text
    for value in sorted(set(filter(None, protected)), key=len, reverse=True):
        redacted = redacted.replace(value, REDACTED_TEXT)
    return _escape_terminal_controls(redacted)


def _escape_terminal_controls(text: str) -> str:
    """保留换行可读性，转义其余控制字符，避免模型文本控制终端。"""
    escaped: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character in "\n\t" or (codepoint >= 32 and codepoint != 127):
            escaped.append(character)
        else:
            escaped.append(f"\\x{codepoint:02x}")
    return "".join(escaped)


def _speaker_block(speaker: str, text: str) -> str:
    lines = text.splitlines() or [""]
    indent = " " * (len(speaker) + 2)
    return "\n".join([f"{speaker}: {lines[0]}", *(f"{indent}{line}" for line in lines[1:])])
