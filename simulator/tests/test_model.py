# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import pytest

from lantern_sim.model import (
    MAX_ENVELOPE_SIZE,
    Encounter,
    Message,
    MessageIdGenerator,
    NodeState,
    SimulationValidationError,
)


def make_message(*, message_id: str = "0" * 32, payload_size: int = 128) -> Message:
    return Message(
        message_id=message_id,
        source="alice",
        destination="bob",
        created_at=0,
        payload_size=payload_size,
    )


def test_message_id_generator_is_repeatable() -> None:
    first = MessageIdGenerator(12345)
    second = MessageIdGenerator(12345)

    assert [first.next_id() for _ in range(3)] == [
        second.next_id() for _ in range(3)
    ]


@pytest.mark.parametrize("payload_size", [1, MAX_ENVELOPE_SIZE])
def test_message_accepts_payload_size_boundaries(payload_size: int) -> None:
    assert make_message(payload_size=payload_size).payload_size == payload_size


@pytest.mark.parametrize("payload_size", [0, MAX_ENVELOPE_SIZE + 1])
def test_message_rejects_payload_outside_boundaries(payload_size: int) -> None:
    with pytest.raises(SimulationValidationError, match="payload_size"):
        make_message(payload_size=payload_size)


@pytest.mark.parametrize(
    "node_id",
    ["", "with space", "../escape", "a" * 65, "узел"],
)
def test_node_rejects_ambiguous_identifier(node_id: str) -> None:
    with pytest.raises(SimulationValidationError, match="node_id"):
        NodeState(node_id)


def test_encounter_requires_two_different_nodes() -> None:
    with pytest.raises(SimulationValidationError, match="different nodes"):
        Encounter(at=10, left="alice", right="alice")


def test_store_deduplicates_identical_message() -> None:
    node = NodeState("relay")
    message = make_message()

    assert node.store(message) is True
    assert node.store(message) is False
    assert node.message_count == 1
    assert node.stored_bytes == message.payload_size


def test_store_rejects_id_collision_with_different_metadata() -> None:
    node = NodeState("relay")
    node.store(make_message(payload_size=128))

    with pytest.raises(SimulationValidationError, match="different message metadata"):
        node.store(make_message(payload_size=256))
