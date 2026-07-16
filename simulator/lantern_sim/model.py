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


@dataclass(frozen=True, slots=True)
class Message:
    """Opaque simulated message metadata without plaintext or cryptography."""

    message_id: str
    source: str
    destination: str
    created_at: int
    payload_size: int

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
        if isinstance(self.payload_size, bool) or not isinstance(
            self.payload_size, int
        ):
            raise SimulationValidationError("payload_size must be an integer")
        if not 1 <= self.payload_size <= MAX_ENVELOPE_SIZE:
            raise SimulationValidationError(
                f"payload_size must be between 1 and {MAX_ENVELOPE_SIZE} bytes"
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
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise SimulationValidationError("seed must be an integer")
        if not 0 <= seed <= MAX_SEED:
            raise SimulationValidationError(
                f"seed must be between 0 and {MAX_SEED}"
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
    """Mutable local store of a simulated node with hard safety limits."""

    node_id: str
    _messages: dict[str, Message] = field(default_factory=dict, init=False)
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

    def messages(self) -> tuple[Message, ...]:
        return tuple(self._messages[key] for key in sorted(self._messages))

    def store(self, message: Message) -> bool:
        """Store a new message and return False for an identical duplicate."""

        existing = self._messages.get(message.message_id)
        if existing is not None:
            if existing != message:
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

        self._messages[message.message_id] = message
        self._stored_bytes += message.payload_size
        return True
