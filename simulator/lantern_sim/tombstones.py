# SPDX-License-Identifier: MPL-2.0

"""Bounded tombstone storage for recently removed message identifiers."""

from __future__ import annotations

from dataclasses import dataclass, field

from lantern_sim.model import (
    MAX_TTL_SECONDS,
    MIN_TTL_SECONDS,
    SimulationValidationError,
    validate_message_id,
)

DEFAULT_MAX_TOMBSTONES = 2_000
MAX_TOMBSTONES = 100_000
DEFAULT_TOMBSTONE_RETENTION_SECONDS = MAX_TTL_SECONDS


def _validate_integer(
    value: int, *, field_name: str, minimum: int, maximum: int
) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SimulationValidationError(f"{field_name} must be an integer")
    if not minimum <= value <= maximum:
        raise SimulationValidationError(
            f"{field_name} must be between {minimum} and {maximum}"
        )


def _validate_non_negative_integer(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SimulationValidationError(f"{field_name} must be an integer")
    if value < 0:
        raise SimulationValidationError(f"{field_name} must not be negative")


@dataclass(frozen=True, slots=True)
class TombstoneConfig:
    max_entries: int = DEFAULT_MAX_TOMBSTONES
    retention_seconds: int = DEFAULT_TOMBSTONE_RETENTION_SECONDS

    def __post_init__(self) -> None:
        _validate_integer(
            self.max_entries,
            field_name="max_entries",
            minimum=1,
            maximum=MAX_TOMBSTONES,
        )
        _validate_integer(
            self.retention_seconds,
            field_name="retention_seconds",
            minimum=MIN_TTL_SECONDS,
            maximum=MAX_TTL_SECONDS,
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "max_entries": self.max_entries,
            "retention_seconds": self.retention_seconds,
        }


@dataclass(frozen=True, slots=True)
class TombstoneEntry:
    message_id: str
    recorded_at: int
    expires_at: int

    def __post_init__(self) -> None:
        validate_message_id(self.message_id)
        _validate_non_negative_integer(self.recorded_at, "recorded_at")
        _validate_non_negative_integer(self.expires_at, "expires_at")
        if self.expires_at <= self.recorded_at:
            raise SimulationValidationError(
                "expires_at must be later than recorded_at"
            )


@dataclass(frozen=True, slots=True)
class TombstoneAddResult:
    entry: TombstoneEntry
    evicted: tuple[TombstoneEntry, ...]


@dataclass(slots=True)
class TombstoneStore:
    config: TombstoneConfig
    _entries: dict[str, TombstoneEntry] = field(default_factory=dict, init=False)

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def entries(self) -> tuple[TombstoneEntry, ...]:
        return tuple(self._entries[key] for key in sorted(self._entries))

    def contains(self, message_id: str, *, at: int) -> bool:
        validate_message_id(message_id)
        self._validate_time(at)
        entry = self._entries.get(message_id)
        if entry is None:
            return False
        if entry.expires_at <= at:
            self._entries.pop(message_id)
            return False
        return True

    def add(self, message_id: str, *, at: int) -> TombstoneAddResult:
        validate_message_id(message_id)
        self._validate_time(at)
        self.purge_expired(at=at)

        entry = TombstoneEntry(
            message_id=message_id,
            recorded_at=at,
            expires_at=at + self.config.retention_seconds,
        )
        if message_id in self._entries:
            self._entries[message_id] = entry
            return TombstoneAddResult(entry=entry, evicted=())

        evicted: tuple[TombstoneEntry, ...] = ()
        if self.entry_count >= self.config.max_entries:
            oldest = min(
                self._entries.values(),
                key=lambda item: (item.recorded_at, item.message_id),
            )
            self._entries.pop(oldest.message_id)
            evicted = (oldest,)

        self._entries[message_id] = entry
        return TombstoneAddResult(entry=entry, evicted=evicted)

    def purge_expired(self, *, at: int) -> tuple[TombstoneEntry, ...]:
        self._validate_time(at)
        expired_ids = tuple(
            message_id
            for message_id, entry in sorted(self._entries.items())
            if entry.expires_at <= at
        )
        expired: list[TombstoneEntry] = []
        for message_id in expired_ids:
            expired.append(self._entries.pop(message_id))
        return tuple(expired)

    @staticmethod
    def _validate_time(at: int) -> None:
        _validate_non_negative_integer(at, "current time")
