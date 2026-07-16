# SPDX-License-Identifier: MPL-2.0

"""Validated data types used by the routing simulator."""

from __future__ import annotations

from dataclasses import dataclass, field
import random
import re

MAX_NODE_ID_LENGTH = 64
MAX_ENVELOPE_SIZE = 64 * 1024
MAX_STORED_MESSAGES_PER_NODE = 1_000
MAX_STORED_BYTES_PER_NODE = 64 * 1024 * 1024
MAX_GENERATED_MESSAGES = 100_000
MAX_SEED = (1 << 64) - 1
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 7 * 24 * 60 * 60
DEFAULT_TTL_SECONDS = 300
MIN_HOPS = 1
MAX_HOPS = 16
DEFAULT_MAX_HOPS = 16
MIN_COPY_BUDGET = 1
MAX_COPY_BUDGET = 64
DEFAULT_COPY_BUDGET = 4

_NODE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]+", re.ASCII)
_MESSAGE_ID_PATTERN = re.compile(r"[0-9a-f]{32}", re.ASCII)


class SimulationValidationError(ValueError):
    """Raised when a simulation input violates a declared constraint."""


class SimulationLimitError(RuntimeError):
    """Raised when a safety limit would be exceeded."""


def validate_node_id(node_id: str) -> None:
    """Validate an unambiguous, bounded simulator node identifier."""

    if not isinstance(node_id, str):
        raise SimulationValidationError("node_id must be a string")
    if not 1 <= len(node_id) <= MAX_NODE_ID_LENGTH:
        raise SimulationValidationError(
            f"node_id length must be between 1 and {MAX_NODE_ID_LENGTH}"
        )
    if _NODE_ID_PATTERN.fullmatch(node_id) is None:
        raise SimulationValidationError(
            "node_id may contain only ASCII letters, digits, '_' and '-'"
        )


def _validate_non_negative_time(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SimulationValidationError(f"{field_name} must be an integer")
    if value < 0:
        raise SimulationValidationError(f"{field_name} must not be negative")


def _validate_bounded_integer(
    value: int, *, field_name: str, minimum: int, maximum: int
) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SimulationValidationError(f"{field_name} must be an integer")
    if not minimum <= value <= maximum:
        raise SimulationValidationError(
            f"{field_name} must be between {minimum} and {maximum}"
        )


@dataclass(frozen=True, slots=True)
class Message:
    """Immutable simulated Envelope metadata without plaintext or cryptography."""

    message_id: str
    source: str
    destination: str
    created_at: int
    payload_size: int
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    max_hops: int = DEFAULT_MAX_HOPS

    def __post_init__(self) -> None:
        if not isinstance(self.message_id, str):
            raise SimulationValidationError("message_id must be a string")
        if _MESSAGE_ID_PATTERN.fullmatch(self.message_id) is None:
            raise SimulationValidationError(
                "message_id must contain exactly 32 lowercase hexadecimal characters"
            )

        validate_node_id(self.source)
        validate_node_id(self.destination)
        if self.source == self.destination:
            raise SimulationValidationError(
                "source and destination must be different nodes"
            )

        _validate_non_negative_time(self.created_at, "created_at")
        _validate_bounded_integer(
            self.payload_size,
            field_name="payload_size",
            minimum=1,
            maximum=MAX_ENVELOPE_SIZE,
        )
        _validate_bounded_integer(
            self.ttl_seconds,
            field_name="ttl_seconds",
            minimum=MIN_TTL_SECONDS,
            maximum=MAX_TTL_SECONDS,
        )
        _validate_bounded_integer(
            self.max_hops,
            field_name="max_hops",
            minimum=MIN_HOPS,
            maximum=MAX_HOPS,
        )


@dataclass(frozen=True, slots=True)
class StoredMessage:
    """One local copy with mutable-route values represented immutably."""

    message: Message
    received_at: int
    remaining_ttl: int
    hops_taken: int
    copies_left: int | None = None

    def __post_init__(self) -> None:
        _validate_non_negative_time(self.received_at, "received_at")
        if self.received_at < self.message.created_at:
            raise SimulationValidationError(
                "received_at must not be earlier than message creation"
            )
        _validate_bounded_integer(
            self.remaining_ttl,
            field_name="remaining_ttl",
            minimum=1,
            maximum=self.message.ttl_seconds,
        )
        _validate_bounded_integer(
            self.hops_taken,
            field_name="hops_taken",
            minimum=0,
            maximum=self.message.max_hops,
        )
        if self.copies_left is not None:
            _validate_bounded_integer(
                self.copies_left,
                field_name="copies_left",
                minimum=MIN_COPY_BUDGET,
                maximum=MAX_COPY_BUDGET,
            )

    @classmethod
    def from_origin(
        cls, message: Message, *, copies_left: int | None = None
    ) -> StoredMessage:
        return cls(
            message=message,
            received_at=message.created_at,
            remaining_ttl=message.ttl_seconds,
            hops_taken=0,
            copies_left=copies_left,
        )

    def remaining_ttl_at(self, at: int) -> int:
        _validate_non_negative_time(at, "current time")
        if at < self.received_at:
            raise SimulationValidationError(
                "current time must not be earlier than received_at"
            )
        return max(0, self.remaining_ttl - (at - self.received_at))

    def forwarded_copy(
        self, at: int, *, copies_left: int | None = None
    ) -> StoredMessage:
        remaining_ttl = self.remaining_ttl_at(at)
        if remaining_ttl == 0:
            raise SimulationValidationError("cannot forward an expired message")
        if self.hops_taken >= self.message.max_hops:
            raise SimulationValidationError("cannot exceed max_hops")
        if (self.copies_left is None) != (copies_left is None):
            raise SimulationValidationError(
                "forwarded copy must preserve copy-budget mode"
            )

        return StoredMessage(
            message=self.message,
            received_at=at,
            remaining_ttl=remaining_ttl,
            hops_taken=self.hops_taken + 1,
            copies_left=copies_left,
        )

    def with_copies_left(self, copies_left: int) -> StoredMessage:
        if self.copies_left is None:
            raise SimulationValidationError(
                "cannot add a copy budget to an unbounded routing copy"
            )
        return StoredMessage(
            message=self.message,
            received_at=self.received_at,
            remaining_ttl=self.remaining_ttl,
            hops_taken=self.hops_taken,
            copies_left=copies_left,
        )


@dataclass(frozen=True, slots=True)
class Encounter:
    """A bidirectional meeting between two nodes at a simulated time."""

    at: int
    left: str
    right: str

    def __post_init__(self) -> None:
        _validate_non_negative_time(self.at, "encounter time")
        validate_node_id(self.left)
        validate_node_id(self.right)
        if self.left == self.right:
            raise SimulationValidationError(
                "an encounter requires two different nodes"
            )


class MessageIdGenerator:
    """Create deterministic simulation-only identifiers from a fixed seed."""

    def __init__(self, seed: int) -> None:
        _validate_bounded_integer(
            seed, field_name="seed", minimum=0, maximum=MAX_SEED
        )
        self._random = random.Random(seed)
        self._issued: set[str] = set()

    def next_id(self) -> str:
        if len(self._issued) >= MAX_GENERATED_MESSAGES:
            raise SimulationLimitError(
                f"cannot generate more than {MAX_GENERATED_MESSAGES} message IDs"
            )

        for _ in range(16):
            candidate = f"{self._random.getrandbits(128):032x}"
            if candidate not in self._issued:
                self._issued.add(candidate)
                return candidate

        raise SimulationLimitError("failed to generate a unique message ID")


@dataclass(slots=True)
class NodeState:
    """Mutable local store of simulated copies with hard safety limits."""

    node_id: str
    _messages: dict[str, StoredMessage] = field(default_factory=dict, init=False)
    _stored_bytes: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        validate_node_id(self.node_id)

    @property
    def message_count(self) -> int:
        return len(self._messages)

    @property
    def stored_bytes(self) -> int:
        return self._stored_bytes

    def has_message(self, message_id: str) -> bool:
        return message_id in self._messages

    def get_message(self, message_id: str) -> StoredMessage | None:
        return self._messages.get(message_id)

    def messages(self) -> tuple[StoredMessage, ...]:
        return tuple(self._messages[key] for key in sorted(self._messages))

    def store_origin(
        self, message: Message, *, copies_left: int | None = None
    ) -> bool:
        return self._store(
            StoredMessage.from_origin(message, copies_left=copies_left)
        )

    def store_forwarded(self, stored_message: StoredMessage) -> bool:
        return self._store(stored_message)

    def _store(self, stored_message: StoredMessage) -> bool:
        message = stored_message.message
        existing = self._messages.get(message.message_id)
        if existing is not None:
            if existing.message != message:
                raise SimulationValidationError(
                    "the same message_id refers to different message metadata"
                )
            return False

        if self.message_count >= MAX_STORED_MESSAGES_PER_NODE:
            raise SimulationLimitError(
                f"node {self.node_id!r} reached the message count limit"
            )
        if self._stored_bytes + message.payload_size > MAX_STORED_BYTES_PER_NODE:
            raise SimulationLimitError(
                f"node {self.node_id!r} reached the storage byte limit"
            )

        self._messages[message.message_id] = stored_message
        self._stored_bytes += message.payload_size
        return True

    def remove(self, message_id: str) -> StoredMessage | None:
        stored_message = self._messages.pop(message_id, None)
        if stored_message is not None:
            self._stored_bytes -= stored_message.message.payload_size
        return stored_message

    def update_copies_left(
        self, expected: StoredMessage, copies_left: int
    ) -> StoredMessage:
        message_id = expected.message.message_id
        current = self._messages.get(message_id)
        if current != expected:
            raise SimulationValidationError(
                "cannot update copy budget for a stale local copy"
            )
        updated = expected.with_copies_left(copies_left)
        self._messages[message_id] = updated
        return updated

    def remove_expired(self, at: int) -> tuple[StoredMessage, ...]:
        expired_ids = tuple(
            message_id
            for message_id, stored_message in sorted(self._messages.items())
            if stored_message.remaining_ttl_at(at) == 0
        )
        removed: list[StoredMessage] = []
        for message_id in expired_ids:
            stored_message = self.remove(message_id)
            if stored_message is not None:
                removed.append(stored_message)
        return tuple(removed)
