"""Atomic replay checkpoints with a process-lifetime, OS-released lock."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from redcell.protocols.common import RedCellModel


class ReplayPersistenceError(RuntimeError):
    """Stop before another paid request if progress cannot be persisted."""


@contextmanager
def replay_lock(path: Path | None) -> Iterator[None]:
    if path is None:
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_name(f"{path.name}.lock").open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ReplayPersistenceError(f"Replay checkpoint is already locked: {path}") from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def save_replay_json(path: Path | None, value: RedCellModel) -> None:
    if path is None:
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(value.model_dump_json(indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise ReplayPersistenceError(f"Cannot persist replay progress: {path}") from exc
    finally:
        temporary.unlink(missing_ok=True)
