# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import pytest

from lantern_sim.model import (
    DEFAULT_COPY_BUDGET,
    Message,
    NodeState,
    SimulationValidationError,
    StoredMessage,
)
from lantern_sim.routing import BinarySprayAndWait, ForwardingDecision


def make_message() -> Message:
    return Message(
        message_id="0" * 32,
        source="alice",
        destination="bob",
        created_at=0,
        payload_size=128,
    )


def store_relay_copy(node: NodeState, *, copies_left: int) -> None:
    node.store_forwarded(
        StoredMessage(
            message=make_message(),
            received_at=10,
            remaining_ttl=290,
            hops_taken=1,
            copies_left=copies_left,
        )
    )


@pytest.mark.parametrize("copy_budget", [1, 64])
def test_spray_and_wait_accepts_copy_budget_boundaries(copy_budget: int) -> None:
    policy = BinarySprayAndWait(copy_budget)

    assert policy.initial_copies_left == copy_budget
    assert policy.parameters == (("copy_budget", copy_budget),)


def test_default_spray_budget_matches_measured_candidate() -> None:
    policy = BinarySprayAndWait()

    assert DEFAULT_COPY_BUDGET == 32
    assert policy.initial_copies_left == 32


@pytest.mark.parametrize("copy_budget", [0, 65, True])
def test_spray_and_wait_rejects_invalid_copy_budget(copy_budget: object) -> None:
    with pytest.raises(SimulationValidationError, match="copy_budget"):
        BinarySprayAndWait(copy_budget)  # type: ignore[arg-type]


def test_binary_spray_splits_odd_budget_without_creating_tokens() -> None:
    sender = NodeState("alice")
    receiver = NodeState("relay")
    sender.store_origin(make_message(), copies_left=5)

    decisions = BinarySprayAndWait(5).forwarding_decisions(sender, receiver)

    assert len(decisions) == 1
    assert decisions[0].sender_copies_left_after == 3
    assert decisions[0].receiver_copies_left == 2


def test_forwarding_decision_rejects_creation_of_extra_tokens() -> None:
    sender = NodeState("alice")
    sender.store_origin(make_message(), copies_left=4)
    stored_message = sender.messages()[0]

    with pytest.raises(SimulationValidationError, match="conserve"):
        ForwardingDecision(
            stored_message=stored_message,
            sender_copies_left_after=3,
            receiver_copies_left=2,
        )


def test_wait_phase_does_not_forward_to_another_relay() -> None:
    sender = NodeState("relay")
    receiver = NodeState("other")
    store_relay_copy(sender, copies_left=1)

    decisions = BinarySprayAndWait(1).forwarding_decisions(sender, receiver)

    assert decisions == ()


def test_wait_phase_allows_transfer_to_destination() -> None:
    sender = NodeState("relay")
    receiver = NodeState("bob")
    store_relay_copy(sender, copies_left=1)

    decisions = BinarySprayAndWait(1).forwarding_decisions(sender, receiver)

    assert len(decisions) == 1
    assert decisions[0].sender_copies_left_after == 0
    assert decisions[0].receiver_copies_left == 1
