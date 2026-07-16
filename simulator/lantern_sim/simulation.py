# SPDX-License-Identifier: MPL-2.0

"""Deterministic event loop and metrics for Lantern routing experiments."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

from lantern_sim.model import (
    Encounter,
    Message,
    NodeState,
    SimulationValidationError,
    StoredMessage,
    validate_node_id,
)
from lantern_sim.routing import RoutingPolicy

MAX_SIMULATION_NODES: Final = 10_000
MAX_SIMULATION_MESSAGES: Final = 100_000
MAX_SIMULATION_ENCOUNTERS: Final = 1_000_000
MAX_SEED: Final = (1 << 64) - 1


class RemovalReason(str, Enum):
    TTL_EXPIRED = "ttl_expired"


class BlockReason(str, Enum):
    HOP_LIMIT_EXCEEDED = "hop_limit_exceeded"
    HOP_LIMIT_BEFORE_DESTINATION = "hop_limit_before_destination"


@dataclass(frozen=True, slots=True)
class Transmission:
    at: int
    sender: str
    receiver: str
    message_id: str
    payload_size: int
    remaining_ttl: int
    hops_taken: int


@dataclass(frozen=True, slots=True)
class Delivery:
    message_id: str
    delivered_at: int
    delay: int


@dataclass(frozen=True, slots=True)
class Removal:
    at: int
    node_id: str
    message_id: str
    reason: RemovalReason


@dataclass(frozen=True, slots=True)
class BlockedTransfer:
    at: int
    sender: str
    receiver: str
    message_id: str
    reason: BlockReason


@dataclass(frozen=True, slots=True)
class SimulationResult:
    seed: int
    policy: str
    node_count: int
    message_count: int
    transmissions: tuple[Transmission, ...]
    deliveries: tuple[Delivery, ...]
    removals: tuple[Removal, ...]
    blocked_transfers: tuple[BlockedTransfer, ...]
    peak_stored_messages: int
    peak_stored_bytes: int

    @property
    def delivered_count(self) -> int:
        return len(self.deliveries)

    @property
    def delivery_rate(self) -> float:
        if self.message_count == 0:
            return 0.0
        return self.delivered_count / self.message_count

    @property
    def transmission_count(self) -> int:
        return len(self.transmissions)

    @property
    def bytes_transmitted(self) -> int:
        return sum(item.payload_size for item in self.transmissions)

    @property
    def average_delivery_delay(self) -> float | None:
        if not self.deliveries:
            return None
        return sum(item.delay for item in self.deliveries) / len(self.deliveries)

    def to_dict(self) -> dict[str, object]:
        return {
            "average_delivery_delay": self.average_delivery_delay,
            "blocked_transfer_count": len(self.blocked_transfers),
            "blocked_transfers": [
                {
                    "at": blocked.at,
                    "message_id": blocked.message_id,
                    "reason": blocked.reason.value,
                    "receiver": blocked.receiver,
                    "sender": blocked.sender,
                }
                for blocked in self.blocked_transfers
            ],
            "bytes_transmitted": self.bytes_transmitted,
            "delivered_count": self.delivered_count,
            "deliveries": [
                {
                    "delay": delivery.delay,
                    "delivered_at": delivery.delivered_at,
                    "message_id": delivery.message_id,
                }
                for delivery in self.deliveries
            ],
            "delivery_rate": self.delivery_rate,
            "message_count": self.message_count,
            "node_count": self.node_count,
            "peak_stored_bytes": self.peak_stored_bytes,
            "peak_stored_messages": self.peak_stored_messages,
            "policy": self.policy,
            "removal_count": len(self.removals),
            "removals": [
                {
                    "at": removal.at,
                    "message_id": removal.message_id,
                    "node_id": removal.node_id,
                    "reason": removal.reason.value,
                }
                for removal in self.removals
            ],
            "seed": self.seed,
            "transmission_count": self.transmission_count,
            "transmissions": [
                {
                    "at": transmission.at,
                    "hops_taken": transmission.hops_taken,
                    "message_id": transmission.message_id,
                    "payload_size": transmission.payload_size,
                    "receiver": transmission.receiver,
                    "remaining_ttl": transmission.remaining_ttl,
                    "sender": transmission.sender,
                }
                for transmission in self.transmissions
            ],
        }


class Simulation:
    """Run a validated list of message creation and encounter events."""

    def __init__(
        self,
        *,
        node_ids: tuple[str, ...],
        messages: tuple[Message, ...],
        encounters: tuple[Encounter, ...],
        seed: int,
    ) -> None:
        self._node_ids = node_ids
        self._messages = messages
        self._encounters = encounters
        self._seed = seed
        self._validate()

    def _validate(self) -> None:
        if not self._node_ids:
            raise SimulationValidationError("simulation requires at least one node")
        if len(self._node_ids) > MAX_SIMULATION_NODES:
            raise SimulationValidationError(
                f"simulation supports at most {MAX_SIMULATION_NODES} nodes"
            )
        if len(self._messages) > MAX_SIMULATION_MESSAGES:
            raise SimulationValidationError(
                f"simulation supports at most {MAX_SIMULATION_MESSAGES} messages"
            )
        if len(self._encounters) > MAX_SIMULATION_ENCOUNTERS:
            raise SimulationValidationError(
                f"simulation supports at most {MAX_SIMULATION_ENCOUNTERS} encounters"
            )
        if isinstance(self._seed, bool) or not isinstance(self._seed, int):
            raise SimulationValidationError("seed must be an integer")
        if not 0 <= self._seed <= MAX_SEED:
            raise SimulationValidationError(
                f"seed must be between 0 and {MAX_SEED}"
            )

        known_nodes: set[str] = set()
        for node_id in self._node_ids:
            validate_node_id(node_id)
            if node_id in known_nodes:
                raise SimulationValidationError(f"duplicate node_id: {node_id!r}")
            known_nodes.add(node_id)

        known_message_ids: set[str] = set()
        for message in self._messages:
            if message.message_id in known_message_ids:
                raise SimulationValidationError(
                    f"duplicate message_id: {message.message_id!r}"
                )
            known_message_ids.add(message.message_id)
            if message.source not in known_nodes:
                raise SimulationValidationError(
                    f"unknown source node: {message.source!r}"
                )
            if message.destination not in known_nodes:
                raise SimulationValidationError(
                    f"unknown destination node: {message.destination!r}"
                )

        for encounter in self._encounters:
            if encounter.left not in known_nodes:
                raise SimulationValidationError(
                    f"unknown encounter node: {encounter.left!r}"
                )
            if encounter.right not in known_nodes:
                raise SimulationValidationError(
                    f"unknown encounter node: {encounter.right!r}"
                )

    def run(self, policy: RoutingPolicy) -> SimulationResult:
        states = {node_id: NodeState(node_id) for node_id in self._node_ids}
        transmissions: list[Transmission] = []
        removals: list[Removal] = []
        blocked_transfers: list[BlockedTransfer] = []
        delivered_at: dict[str, int] = {}
        peak_stored_messages = 0
        peak_stored_bytes = 0

        def update_peaks() -> None:
            nonlocal peak_stored_messages, peak_stored_bytes
            stored_messages = sum(state.message_count for state in states.values())
            stored_bytes = sum(state.stored_bytes for state in states.values())
            peak_stored_messages = max(peak_stored_messages, stored_messages)
            peak_stored_bytes = max(peak_stored_bytes, stored_bytes)

        events: list[tuple[int, int, int, Message | Encounter]] = []
        events.extend(
            (message.created_at, 0, index, message)
            for index, message in enumerate(self._messages)
        )
        events.extend(
            (encounter.at, 1, index, encounter)
            for index, encounter in enumerate(self._encounters)
        )
        events.sort(key=lambda event: (event[0], event[1], event[2]))

        for at, event_kind, _, event in events:
            self._remove_expired(at=at, states=states, removals=removals)

            if event_kind == 0:
                if not isinstance(event, Message):
                    raise AssertionError("message event has an invalid type")
                states[event.source].store_origin(event)
                update_peaks()
                continue

            if not isinstance(event, Encounter):
                raise AssertionError("encounter event has an invalid type")

            left = states[event.left]
            right = states[event.right]
            left_to_right = policy.messages_to_forward(left, right)
            right_to_left = policy.messages_to_forward(right, left)

            self._transfer(
                at=at,
                sender=left,
                receiver=right,
                messages=left_to_right,
                transmissions=transmissions,
                delivered_at=delivered_at,
                blocked_transfers=blocked_transfers,
            )
            self._transfer(
                at=at,
                sender=right,
                receiver=left,
                messages=right_to_left,
                transmissions=transmissions,
                delivered_at=delivered_at,
                blocked_transfers=blocked_transfers,
            )
            update_peaks()

        messages_by_id = {message.message_id: message for message in self._messages}
        deliveries = tuple(
            Delivery(
                message_id=message_id,
                delivered_at=delivery_time,
                delay=delivery_time - messages_by_id[message_id].created_at,
            )
            for message_id, delivery_time in sorted(delivered_at.items())
        )

        return SimulationResult(
            seed=self._seed,
            policy=policy.name,
            node_count=len(states),
            message_count=len(self._messages),
            transmissions=tuple(transmissions),
            deliveries=deliveries,
            removals=tuple(removals),
            blocked_transfers=tuple(blocked_transfers),
            peak_stored_messages=peak_stored_messages,
            peak_stored_bytes=peak_stored_bytes,
        )

    @staticmethod
    def _remove_expired(
        *,
        at: int,
        states: dict[str, NodeState],
        removals: list[Removal],
    ) -> None:
        for node_id, state in states.items():
            for stored_message in state.remove_expired(at):
                removals.append(
                    Removal(
                        at=at,
                        node_id=node_id,
                        message_id=stored_message.message.message_id,
                        reason=RemovalReason.TTL_EXPIRED,
                    )
                )

    @staticmethod
    def _transfer(
        *,
        at: int,
        sender: NodeState,
        receiver: NodeState,
        messages: tuple[StoredMessage, ...],
        transmissions: list[Transmission],
        delivered_at: dict[str, int],
        blocked_transfers: list[BlockedTransfer],
    ) -> None:
        for stored_message in messages:
            message = stored_message.message
            current = sender.get_message(message.message_id)
            if current != stored_message:
                raise SimulationValidationError(
                    "routing policy selected a stale or missing local copy"
                )

            next_hops = stored_message.hops_taken + 1
            if next_hops > message.max_hops:
                blocked_transfers.append(
                    BlockedTransfer(
                        at=at,
                        sender=sender.node_id,
                        receiver=receiver.node_id,
                        message_id=message.message_id,
                        reason=BlockReason.HOP_LIMIT_EXCEEDED,
                    )
                )
                continue
            if (
                next_hops == message.max_hops
                and receiver.node_id != message.destination
            ):
                blocked_transfers.append(
                    BlockedTransfer(
                        at=at,
                        sender=sender.node_id,
                        receiver=receiver.node_id,
                        message_id=message.message_id,
                        reason=BlockReason.HOP_LIMIT_BEFORE_DESTINATION,
                    )
                )
                continue

            forwarded_copy = stored_message.forwarded_copy(at)
            if not receiver.store_forwarded(forwarded_copy):
                continue

            transmissions.append(
                Transmission(
                    at=at,
                    sender=sender.node_id,
                    receiver=receiver.node_id,
                    message_id=message.message_id,
                    payload_size=message.payload_size,
                    remaining_ttl=forwarded_copy.remaining_ttl,
                    hops_taken=forwarded_copy.hops_taken,
                )
            )
            if receiver.node_id == message.destination:
                delivered_at.setdefault(message.message_id, at)
