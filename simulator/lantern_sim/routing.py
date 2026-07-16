# SPDX-License-Identifier: MPL-2.0

"""Routing policies that operate on opaque simulated messages."""

from __future__ import annotations

from typing import Protocol

from lantern_sim.model import NodeState, StoredMessage


class RoutingPolicy(Protocol):
    """Select local copies for one direction of an encounter."""

    name: str

    def messages_to_forward(
        self, sender: NodeState, receiver: NodeState
    ) -> tuple[StoredMessage, ...]:
        """Return a deterministic, bounded tuple of copies to forward."""


class DirectDelivery:
    """Forward only messages addressed to the current peer."""

    name = "direct"

    def messages_to_forward(
        self, sender: NodeState, receiver: NodeState
    ) -> tuple[StoredMessage, ...]:
        return tuple(
            stored_message
            for stored_message in sender.messages()
            if stored_message.message.destination == receiver.node_id
            and not receiver.has_message(stored_message.message.message_id)
        )


class EpidemicRouting:
    """Forward every message unknown to the current peer."""

    name = "epidemic"

    def messages_to_forward(
        self, sender: NodeState, receiver: NodeState
    ) -> tuple[StoredMessage, ...]:
        return tuple(
            stored_message
            for stored_message in sender.messages()
            if not receiver.has_message(stored_message.message.message_id)
        )
