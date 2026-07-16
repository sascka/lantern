# SPDX-License-Identifier: MPL-2.0

"""Routing policies that operate on opaque simulated messages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from lantern_sim.model import (
    DEFAULT_COPY_BUDGET,
    MAX_COPY_BUDGET,
    MIN_COPY_BUDGET,
    NodeState,
    SimulationValidationError,
    StoredMessage,
)


@dataclass(frozen=True, slots=True)
class ForwardingDecision:
    """One selected copy and the copy-budget split after transmission."""

    stored_message: StoredMessage
    sender_copies_left_after: int | None = None
    receiver_copies_left: int | None = None

    def __post_init__(self) -> None:
        current = self.stored_message.copies_left
        if current is None:
            if (
                self.sender_copies_left_after is not None
                or self.receiver_copies_left is not None
            ):
                raise SimulationValidationError(
                    "unbounded routing must not create a copy budget"
                )
            return

        sender_after = self.sender_copies_left_after
        receiver_copies = self.receiver_copies_left
        if (
            isinstance(sender_after, bool)
            or not isinstance(sender_after, int)
            or sender_after < 0
        ):
            raise SimulationValidationError(
                "sender_copies_left_after must be a non-negative integer"
            )
        if (
            isinstance(receiver_copies, bool)
            or not isinstance(receiver_copies, int)
            or receiver_copies < 1
        ):
            raise SimulationValidationError(
                "receiver_copies_left must be a positive integer"
            )
        if sender_after + receiver_copies != current:
            raise SimulationValidationError(
                "forwarding decision must conserve the copy budget"
            )


class RoutingPolicy(Protocol):
    """Select local copies for one direction of an encounter."""

    name: str
    initial_copies_left: int | None
    parameters: tuple[tuple[str, int], ...]

    def forwarding_decisions(
        self, sender: NodeState, receiver: NodeState
    ) -> tuple[ForwardingDecision, ...]:
        """Return deterministic, bounded decisions for one direction."""


class DirectDelivery:
    """Forward only messages addressed to the current peer."""

    name = "direct"
    initial_copies_left = None
    parameters: tuple[tuple[str, int], ...] = ()

    def forwarding_decisions(
        self, sender: NodeState, receiver: NodeState
    ) -> tuple[ForwardingDecision, ...]:
        return tuple(
            ForwardingDecision(stored_message)
            for stored_message in sender.messages()
            if stored_message.message.destination == receiver.node_id
            and not receiver.has_message(stored_message.message.message_id)
        )


class EpidemicRouting:
    """Forward every message unknown to the current peer."""

    name = "epidemic"
    initial_copies_left = None
    parameters: tuple[tuple[str, int], ...] = ()

    def forwarding_decisions(
        self, sender: NodeState, receiver: NodeState
    ) -> tuple[ForwardingDecision, ...]:
        return tuple(
            ForwardingDecision(stored_message)
            for stored_message in sender.messages()
            if not receiver.has_message(stored_message.message.message_id)
        )


class BinarySprayAndWait:
    """Split copy tokens in half, then wait for the destination."""

    name = "spray_and_wait"

    def __init__(self, copy_budget: int = DEFAULT_COPY_BUDGET) -> None:
        if isinstance(copy_budget, bool) or not isinstance(copy_budget, int):
            raise SimulationValidationError("copy_budget must be an integer")
        if not MIN_COPY_BUDGET <= copy_budget <= MAX_COPY_BUDGET:
            raise SimulationValidationError(
                "copy_budget must be between "
                f"{MIN_COPY_BUDGET} and {MAX_COPY_BUDGET}"
            )
        self.initial_copies_left = copy_budget
        self.parameters = (("copy_budget", copy_budget),)

    def forwarding_decisions(
        self, sender: NodeState, receiver: NodeState
    ) -> tuple[ForwardingDecision, ...]:
        decisions: list[ForwardingDecision] = []
        for stored_message in sender.messages():
            message = stored_message.message
            if message.destination == sender.node_id:
                continue
            if receiver.has_message(message.message_id):
                continue

            copies_left = stored_message.copies_left
            if copies_left is None:
                raise SimulationValidationError(
                    "Spray-and-Wait requires a copy budget on every local copy"
                )

            if receiver.node_id == message.destination:
                receiver_copies = 1
            elif copies_left > 1:
                receiver_copies = copies_left // 2
            else:
                continue

            decisions.append(
                ForwardingDecision(
                    stored_message=stored_message,
                    sender_copies_left_after=copies_left - receiver_copies,
                    receiver_copies_left=receiver_copies,
                )
            )
        return tuple(decisions)
