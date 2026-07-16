# SPDX-License-Identifier: MPL-2.0

"""Routing policies that operate on opaque simulated messages."""

from __future__ import annotations

from typing import Protocol

from lantern_sim.model import Message, NodeState


class RoutingPolicy(Protocol):
    """Select messages for one direction of an encounter."""

    name: str

    def messages_to_forward(
        self, sender: NodeState, receiver: NodeState
    ) -> tuple[Message, ...]:
        """Return a deterministic, bounded tuple of messages to forward."""


class DirectDelivery:
    """Forward only messages addressed to the current peer."""

    name = "direct"

    def messages_to_forward(
        self, sender: NodeState, receiver: NodeState
    ) -> tuple[Message, ...]:
        return tuple(
            message
            for message in sender.messages()
            if message.destination == receiver.node_id
            and not receiver.has_message(message.message_id)
        )


class EpidemicRouting:
    """Forward every message unknown to the current peer."""

    name = "epidemic"

    def messages_to_forward(
        self, sender: NodeState, receiver: NodeState
    ) -> tuple[Message, ...]:
        return tuple(
            message
            for message in sender.messages()
            if not receiver.has_message(message.message_id)
        )
