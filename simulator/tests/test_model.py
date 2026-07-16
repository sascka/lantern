# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import pytest

from lantern_sim.model import (
    MAX_HOPS,
    MAX_ENVELOPE_SIZE,
    MAX_TTL_SECONDS,
    MIN_HOPS,
    MIN_TTL_SECONDS,
    Encounter,
    Message,
    MessageIdGenerator,
    NodeState,
    SimulationValidationError,
    StoredMessage,
)


def make_message(
    *,
    message_id: str = "0" * 32,
    payload_size: int = 128,
    ttl_seconds: int = 300,
    max_hops: int = 16,
) -> Message:
    return Message(
        message_id=message_id,
        source="alice",
        destination="bob",
        created_at=0,
        payload_size=payload_size,
        ttl_seconds=ttl_seconds,
        max_hops=max_hops,
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


@pytest.mark.parametrize("ttl_seconds", [MIN_TTL_SECONDS, MAX_TTL_SECONDS])
def test_message_accepts_ttl_boundaries(ttl_seconds: int) -> None:
    assert make_message(ttl_seconds=ttl_seconds).ttl_seconds == ttl_seconds


@pytest.mark.parametrize(
    "ttl_seconds", [MIN_TTL_SECONDS - 1, MAX_TTL_SECONDS + 1]
)
def test_message_rejects_ttl_outside_boundaries(ttl_seconds: int) -> None:
    with pytest.raises(SimulationValidationError, match="ttl_seconds"):
        make_message(ttl_seconds=ttl_seconds)


@pytest.mark.parametrize("max_hops", [MIN_HOPS, MAX_HOPS])
def test_message_accepts_hop_boundaries(max_hops: int) -> None:
    assert make_message(max_hops=max_hops).max_hops == max_hops


@pytest.mark.parametrize("max_hops", [MIN_HOPS - 1, MAX_HOPS + 1])
def test_message_rejects_hops_outside_boundaries(max_hops: int) -> None:
    with pytest.raises(SimulationValidationError, match="max_hops"):
        make_message(max_hops=max_hops)


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

    assert node.store_origin(message) is True
    assert node.store_origin(message) is False
    assert node.message_count == 1
    assert node.stored_bytes == message.payload_size


def test_store_rejects_id_collision_with_different_metadata() -> None:
    node = NodeState("relay")
    node.store_origin(make_message(payload_size=128))

    with pytest.raises(SimulationValidationError, match="different message metadata"):
        node.store_origin(make_message(payload_size=256))


def test_forwarded_copy_decreases_ttl_and_increases_hops() -> None:
    origin = StoredMessage.from_origin(make_message(ttl_seconds=300, max_hops=3))

    forwarded = origin.forwarded_copy(at=25)

    assert forwarded.received_at == 25
    assert forwarded.remaining_ttl == 275
    assert forwarded.hops_taken == 1
    assert forwarded.message == origin.message


def test_node_removes_expired_copy_and_updates_storage() -> None:
    node = NodeState("relay")
    message = make_message(ttl_seconds=60)
    node.store_origin(message)

    assert node.remove_expired(at=59) == ()
    removed = node.remove_expired(at=60)

    assert tuple(item.message for item in removed) == (message,)
    assert node.message_count == 0
    assert node.stored_bytes == 0
