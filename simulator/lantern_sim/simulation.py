# SPDX-License-Identifier: MPL-2.0

"""Deterministic event loop and metrics for Lantern routing experiments."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

from lantern_sim.faults import NetworkConditions
from lantern_sim.model import (
    Encounter,
    Message,
    NodeState,
    SimulationValidationError,
    StorageQuota,
    StoreOutcome,
    StoreResult,
    validate_node_id,
)
from lantern_sim.routing import ForwardingDecision, RoutingPolicy
from lantern_sim.tombstones import (
    TombstoneConfig,
    TombstoneStore,
)

MAX_SIMULATION_NODES: Final = 10_000
MAX_SIMULATION_MESSAGES: Final = 100_000
MAX_SIMULATION_ENCOUNTERS: Final = 1_000_000
MAX_SEED: Final = (1 << 64) - 1


class RemovalReason(str, Enum):
    TTL_EXPIRED = "ttl_expired"
    QUOTA_EVICTED = "quota_evicted"


class BlockReason(str, Enum):
    HOP_LIMIT_EXCEEDED = "hop_limit_exceeded"
    HOP_LIMIT_BEFORE_DESTINATION = "hop_limit_before_destination"


class AttemptOutcome(str, Enum):
    STORED = "stored"
    LOST = "lost"
    DUPLICATE_IGNORED = "duplicate_ignored"
    QUOTA_REJECTED = "quota_rejected"
    TOMBSTONE_REJECTED = "tombstone_rejected"


class TombstoneEventReason(str, Enum):
    EXPIRED = "expired"
    CAPACITY_EVICTED = "capacity_evicted"


@dataclass(frozen=True, slots=True)
class TransferAttempt:
    at: int
    sender: str
    receiver: str
    message_id: str
    payload_size: int
    outcome: AttemptOutcome


@dataclass(frozen=True, slots=True)
class Transmission:
    at: int
    sender: str
    receiver: str
    message_id: str
    payload_size: int
    remaining_ttl: int
    hops_taken: int
    sender_copies_left_after: int | None
    receiver_copies_left: int | None


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
class StorageRejection:
    at: int
    node_id: str
    message_id: str
    reason: StoreOutcome


@dataclass(frozen=True, slots=True)
class TombstoneRejection:
    at: int
    node_id: str
    message_id: str


@dataclass(frozen=True, slots=True)
class TombstoneEvent:
    at: int
    node_id: str
    message_id: str
    reason: TombstoneEventReason


@dataclass(frozen=True, slots=True)
class SimulationResult:
    seed: int
    policy: str
    policy_parameters: tuple[tuple[str, int], ...]
    network_conditions: NetworkConditions
    storage_quota: StorageQuota
    tombstone_config: TombstoneConfig
    node_count: int
    message_count: int
    attempts: tuple[TransferAttempt, ...]
    transmissions: tuple[Transmission, ...]
    deliveries: tuple[Delivery, ...]
    removals: tuple[Removal, ...]
    storage_rejections: tuple[StorageRejection, ...]
    tombstone_rejections: tuple[TombstoneRejection, ...]
    tombstone_events: tuple[TombstoneEvent, ...]
    blocked_transfers: tuple[BlockedTransfer, ...]
    peak_stored_messages: int
    peak_stored_bytes: int
    peak_node_stored_messages: int
    peak_node_stored_bytes: int
    peak_node_tombstones: int

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
    def attempt_count(self) -> int:
        return len(self.attempts)

    @property
    def bytes_transmitted(self) -> int:
        return sum(item.payload_size for item in self.transmissions)

    @property
    def bytes_attempted(self) -> int:
        return sum(item.payload_size for item in self.attempts)

    @property
    def lost_attempt_count(self) -> int:
        return sum(item.outcome is AttemptOutcome.LOST for item in self.attempts)

    @property
    def duplicate_attempt_count(self) -> int:
        return sum(
            item.outcome is AttemptOutcome.DUPLICATE_IGNORED
            for item in self.attempts
        )

    @property
    def eviction_count(self) -> int:
        return sum(
            item.reason is RemovalReason.QUOTA_EVICTED for item in self.removals
        )

    @property
    def quota_rejection_count(self) -> int:
        return len(self.storage_rejections)

    @property
    def tombstone_rejection_count(self) -> int:
        return len(self.tombstone_rejections)

    @property
    def average_delivery_delay(self) -> float | None:
        if not self.deliveries:
            return None
        return sum(item.delay for item in self.deliveries) / len(self.deliveries)

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt_count": self.attempt_count,
            "attempts": [
                {
                    "at": attempt.at,
                    "message_id": attempt.message_id,
                    "outcome": attempt.outcome.value,
                    "payload_size": attempt.payload_size,
                    "receiver": attempt.receiver,
                    "sender": attempt.sender,
                }
                for attempt in self.attempts
            ],
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
            "bytes_attempted": self.bytes_attempted,
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
            "duplicate_attempt_count": self.duplicate_attempt_count,
            "eviction_count": self.eviction_count,
            "lost_attempt_count": self.lost_attempt_count,
            "message_count": self.message_count,
            "node_count": self.node_count,
            "network_conditions": self.network_conditions.to_dict(),
            "peak_stored_bytes": self.peak_stored_bytes,
            "peak_stored_messages": self.peak_stored_messages,
            "peak_node_stored_bytes": self.peak_node_stored_bytes,
            "peak_node_stored_messages": self.peak_node_stored_messages,
            "peak_node_tombstones": self.peak_node_tombstones,
            "policy": self.policy,
            "policy_parameters": dict(self.policy_parameters),
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
            "quota_rejection_count": self.quota_rejection_count,
            "seed": self.seed,
            "storage_quota": self.storage_quota.to_dict(),
            "storage_rejections": [
                {
                    "at": rejection.at,
                    "message_id": rejection.message_id,
                    "node_id": rejection.node_id,
                    "reason": rejection.reason.value,
                }
                for rejection in self.storage_rejections
            ],
            "tombstone_config": self.tombstone_config.to_dict(),
            "tombstone_event_count": len(self.tombstone_events),
            "tombstone_events": [
                {
                    "at": event.at,
                    "message_id": event.message_id,
                    "node_id": event.node_id,
                    "reason": event.reason.value,
                }
                for event in self.tombstone_events
            ],
            "tombstone_rejection_count": self.tombstone_rejection_count,
            "tombstone_rejections": [
                {
                    "at": rejection.at,
                    "message_id": rejection.message_id,
                    "node_id": rejection.node_id,
                }
                for rejection in self.tombstone_rejections
            ],
            "transmission_count": self.transmission_count,
            "transmissions": [
                {
                    "at": transmission.at,
                    "hops_taken": transmission.hops_taken,
                    "message_id": transmission.message_id,
                    "payload_size": transmission.payload_size,
                    "receiver": transmission.receiver,
                    "receiver_copies_left": transmission.receiver_copies_left,
                    "remaining_ttl": transmission.remaining_ttl,
                    "sender": transmission.sender,
                    "sender_copies_left_after": (
                        transmission.sender_copies_left_after
                    ),
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

    def run(
        self,
        policy: RoutingPolicy,
        network_conditions: NetworkConditions | None = None,
        storage_quota: StorageQuota | None = None,
        tombstone_config: TombstoneConfig | None = None,
    ) -> SimulationResult:
        conditions = network_conditions or NetworkConditions()
        quota = storage_quota or StorageQuota()
        tombstone_settings = tombstone_config or TombstoneConfig()
        states = {node_id: NodeState(node_id) for node_id in self._node_ids}
        tombstones = {
            node_id: TombstoneStore(tombstone_settings)
            for node_id in self._node_ids
        }
        attempts: list[TransferAttempt] = []
        transmissions: list[Transmission] = []
        removals: list[Removal] = []
        storage_rejections: list[StorageRejection] = []
        tombstone_rejections: list[TombstoneRejection] = []
        tombstone_events: list[TombstoneEvent] = []
        blocked_transfers: list[BlockedTransfer] = []
        delivered_at: dict[str, int] = {}
        peak_stored_messages = 0
        peak_stored_bytes = 0
        peak_node_stored_messages = 0
        peak_node_stored_bytes = 0
        peak_node_tombstones = 0

        def update_peaks() -> None:
            nonlocal peak_stored_messages, peak_stored_bytes
            nonlocal peak_node_stored_messages, peak_node_stored_bytes
            nonlocal peak_node_tombstones
            stored_messages = sum(state.message_count for state in states.values())
            stored_bytes = sum(state.stored_bytes for state in states.values())
            peak_stored_messages = max(peak_stored_messages, stored_messages)
            peak_stored_bytes = max(peak_stored_bytes, stored_bytes)
            peak_node_stored_messages = max(
                peak_node_stored_messages,
                max(state.message_count for state in states.values()),
            )
            peak_node_stored_bytes = max(
                peak_node_stored_bytes,
                max(state.stored_bytes for state in states.values()),
            )
            peak_node_tombstones = max(
                peak_node_tombstones,
                max(store.entry_count for store in tombstones.values()),
            )

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

        for at, event_kind, event_index, event in events:
            self._purge_tombstones(
                at=at,
                tombstones=tombstones,
                tombstone_events=tombstone_events,
            )
            self._remove_expired(
                at=at,
                states=states,
                removals=removals,
                tombstones=tombstones,
                tombstone_events=tombstone_events,
            )

            if event_kind == 0:
                if not isinstance(event, Message):
                    raise AssertionError("message event has an invalid type")
                store_result = states[event.source].store_origin_with_eviction(
                    event,
                    copies_left=policy.initial_copies_left,
                    quota=quota,
                )
                self._record_store_result(
                    at=at,
                    node_id=event.source,
                    message_id=event.message_id,
                    result=store_result,
                    removals=removals,
                    storage_rejections=storage_rejections,
                    tombstone_store=tombstones[event.source],
                    tombstone_events=tombstone_events,
                )
                update_peaks()
                continue

            if not isinstance(event, Encounter):
                raise AssertionError("encounter event has an invalid type")

            left = states[event.left]
            right = states[event.right]
            left_to_right = conditions.order_batch(
                policy.forwarding_decisions(left, right)
            )

            self._transfer(
                at=at,
                encounter_index=event_index,
                sender=left,
                receiver=right,
                messages=left_to_right,
                attempts=attempts,
                transmissions=transmissions,
                delivered_at=delivered_at,
                blocked_transfers=blocked_transfers,
                network_conditions=conditions,
                storage_quota=quota,
                removals=removals,
                storage_rejections=storage_rejections,
                tombstone_store=tombstones[right.node_id],
                tombstone_rejections=tombstone_rejections,
                tombstone_events=tombstone_events,
                seed=self._seed,
            )
            update_peaks()

            right_to_left = conditions.order_batch(
                policy.forwarding_decisions(right, left)
            )
            self._transfer(
                at=at,
                encounter_index=event_index,
                sender=right,
                receiver=left,
                messages=right_to_left,
                attempts=attempts,
                transmissions=transmissions,
                delivered_at=delivered_at,
                blocked_transfers=blocked_transfers,
                network_conditions=conditions,
                storage_quota=quota,
                removals=removals,
                storage_rejections=storage_rejections,
                tombstone_store=tombstones[left.node_id],
                tombstone_rejections=tombstone_rejections,
                tombstone_events=tombstone_events,
                seed=self._seed,
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
            policy_parameters=policy.parameters,
            network_conditions=conditions,
            storage_quota=quota,
            tombstone_config=tombstone_settings,
            node_count=len(states),
            message_count=len(self._messages),
            attempts=tuple(attempts),
            transmissions=tuple(transmissions),
            deliveries=deliveries,
            removals=tuple(removals),
            storage_rejections=tuple(storage_rejections),
            tombstone_rejections=tuple(tombstone_rejections),
            tombstone_events=tuple(tombstone_events),
            blocked_transfers=tuple(blocked_transfers),
            peak_stored_messages=peak_stored_messages,
            peak_stored_bytes=peak_stored_bytes,
            peak_node_stored_messages=peak_node_stored_messages,
            peak_node_stored_bytes=peak_node_stored_bytes,
            peak_node_tombstones=peak_node_tombstones,
        )

    @staticmethod
    def _record_store_result(
        *,
        at: int,
        node_id: str,
        message_id: str,
        result: StoreResult,
        removals: list[Removal],
        storage_rejections: list[StorageRejection],
        tombstone_store: TombstoneStore,
        tombstone_events: list[TombstoneEvent],
    ) -> None:
        for evicted in result.evicted:
            removals.append(
                Removal(
                    at=at,
                    node_id=node_id,
                    message_id=evicted.message.message_id,
                    reason=RemovalReason.QUOTA_EVICTED,
                )
            )
            Simulation._add_tombstone(
                at=at,
                node_id=node_id,
                message_id=evicted.message.message_id,
                tombstone_store=tombstone_store,
                tombstone_events=tombstone_events,
            )
        if result.outcome is StoreOutcome.ITEM_EXCEEDS_BYTE_QUOTA:
            storage_rejections.append(
                StorageRejection(
                    at=at,
                    node_id=node_id,
                    message_id=message_id,
                    reason=result.outcome,
                )
            )

    @staticmethod
    def _add_tombstone(
        *,
        at: int,
        node_id: str,
        message_id: str,
        tombstone_store: TombstoneStore,
        tombstone_events: list[TombstoneEvent],
    ) -> None:
        result = tombstone_store.add(message_id, at=at)
        for evicted in result.evicted:
            tombstone_events.append(
                TombstoneEvent(
                    at=at,
                    node_id=node_id,
                    message_id=evicted.message_id,
                    reason=TombstoneEventReason.CAPACITY_EVICTED,
                )
            )

    @staticmethod
    def _purge_tombstones(
        *,
        at: int,
        tombstones: dict[str, TombstoneStore],
        tombstone_events: list[TombstoneEvent],
    ) -> None:
        for node_id, store in tombstones.items():
            for expired in store.purge_expired(at=at):
                tombstone_events.append(
                    TombstoneEvent(
                        at=at,
                        node_id=node_id,
                        message_id=expired.message_id,
                        reason=TombstoneEventReason.EXPIRED,
                    )
                )

    @staticmethod
    def _remove_expired(
        *,
        at: int,
        states: dict[str, NodeState],
        removals: list[Removal],
        tombstones: dict[str, TombstoneStore],
        tombstone_events: list[TombstoneEvent],
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
                Simulation._add_tombstone(
                    at=at,
                    node_id=node_id,
                    message_id=stored_message.message.message_id,
                    tombstone_store=tombstones[node_id],
                    tombstone_events=tombstone_events,
                )

    @staticmethod
    def _transfer(
        *,
        at: int,
        encounter_index: int,
        sender: NodeState,
        receiver: NodeState,
        messages: tuple[ForwardingDecision, ...],
        attempts: list[TransferAttempt],
        transmissions: list[Transmission],
        delivered_at: dict[str, int],
        blocked_transfers: list[BlockedTransfer],
        network_conditions: NetworkConditions,
        storage_quota: StorageQuota,
        removals: list[Removal],
        storage_rejections: list[StorageRejection],
        tombstone_store: TombstoneStore,
        tombstone_rejections: list[TombstoneRejection],
        tombstone_events: list[TombstoneEvent],
        seed: int,
    ) -> None:
        for decision in messages:
            stored_message = decision.stored_message
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

            forwarded_copy = stored_message.forwarded_copy(
                at, copies_left=decision.receiver_copies_left
            )
            if network_conditions.is_lost(
                seed=seed,
                encounter_index=encounter_index,
                sender=sender.node_id,
                receiver=receiver.node_id,
                message_id=message.message_id,
            ):
                attempts.append(
                    TransferAttempt(
                        at=at,
                        sender=sender.node_id,
                        receiver=receiver.node_id,
                        message_id=message.message_id,
                        payload_size=message.payload_size,
                        outcome=AttemptOutcome.LOST,
                    )
                )
                continue

            if tombstone_store.contains(message.message_id, at=at):
                attempts.append(
                    TransferAttempt(
                        at=at,
                        sender=sender.node_id,
                        receiver=receiver.node_id,
                        message_id=message.message_id,
                        payload_size=message.payload_size,
                        outcome=AttemptOutcome.TOMBSTONE_REJECTED,
                    )
                )
                tombstone_rejections.append(
                    TombstoneRejection(
                        at=at,
                        node_id=receiver.node_id,
                        message_id=message.message_id,
                    )
                )
                continue

            store_result = receiver.store_forwarded_with_eviction(
                forwarded_copy, quota=storage_quota
            )
            if store_result.outcome is StoreOutcome.DUPLICATE:
                attempts.append(
                    TransferAttempt(
                        at=at,
                        sender=sender.node_id,
                        receiver=receiver.node_id,
                        message_id=message.message_id,
                        payload_size=message.payload_size,
                        outcome=AttemptOutcome.DUPLICATE_IGNORED,
                    )
                )
                continue
            if not store_result.stored:
                attempts.append(
                    TransferAttempt(
                        at=at,
                        sender=sender.node_id,
                        receiver=receiver.node_id,
                        message_id=message.message_id,
                        payload_size=message.payload_size,
                        outcome=AttemptOutcome.QUOTA_REJECTED,
                    )
                )
                Simulation._record_store_result(
                    at=at,
                    node_id=receiver.node_id,
                    message_id=message.message_id,
                    result=store_result,
                    removals=removals,
                    storage_rejections=storage_rejections,
                    tombstone_store=tombstone_store,
                    tombstone_events=tombstone_events,
                )
                continue

            Simulation._record_store_result(
                at=at,
                node_id=receiver.node_id,
                message_id=message.message_id,
                result=store_result,
                removals=removals,
                storage_rejections=storage_rejections,
                tombstone_store=tombstone_store,
                tombstone_events=tombstone_events,
            )

            attempts.append(
                TransferAttempt(
                    at=at,
                    sender=sender.node_id,
                    receiver=receiver.node_id,
                    message_id=message.message_id,
                    payload_size=message.payload_size,
                    outcome=AttemptOutcome.STORED,
                )
            )

            sender_copies_after = decision.sender_copies_left_after
            if sender_copies_after == 0:
                removed = sender.remove(message.message_id)
                if removed != stored_message:
                    raise SimulationValidationError(
                        "failed to remove the expected exhausted copy"
                    )
            elif sender_copies_after is not None:
                sender.update_copies_left(stored_message, sender_copies_after)

            transmissions.append(
                Transmission(
                    at=at,
                    sender=sender.node_id,
                    receiver=receiver.node_id,
                    message_id=message.message_id,
                    payload_size=message.payload_size,
                    remaining_ttl=forwarded_copy.remaining_ttl,
                    hops_taken=forwarded_copy.hops_taken,
                    sender_copies_left_after=sender_copies_after,
                    receiver_copies_left=forwarded_copy.copies_left,
                )
            )
            if receiver.node_id == message.destination:
                delivered_at.setdefault(message.message_id, at)

            if network_conditions.is_duplicated(
                seed=seed,
                encounter_index=encounter_index,
                sender=sender.node_id,
                receiver=receiver.node_id,
                message_id=message.message_id,
            ):
                if receiver.store_forwarded(forwarded_copy):
                    raise SimulationValidationError(
                        "duplicate transfer unexpectedly created a second copy"
                    )
                attempts.append(
                    TransferAttempt(
                        at=at,
                        sender=sender.node_id,
                        receiver=receiver.node_id,
                        message_id=message.message_id,
                        payload_size=message.payload_size,
                        outcome=AttemptOutcome.DUPLICATE_IGNORED,
                    )
                )
