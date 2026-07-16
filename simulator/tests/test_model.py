# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import random

import pytest

from lantern_sim.model import (
    MAX_ENVELOPE_SIZE,
    MAX_HOPS,
    MAX_TTL_SECONDS,
    MIN_HOPS,
    MIN_TTL_SECONDS,
    Encounter,
    Message,
    MessageIdGenerator,
    NodeState,
    SimulationValidationError,
    StorageQuota,
    StoredMessage,
    StoreOutcome,
)


def make_message(
    *,
    message_id: str = "0" * 32,
    created_at: int = 0,
    payload_size: int = 128,
    ttl_seconds: int = 300,
    max_hops: int = 16,
) -> Message:
    return Message(
        message_id=message_id,
        source="alice",
        destination="bob",
        created_at=created_at,
        payload_size=payload_size,
        ttl_seconds=ttl_seconds,
        max_hops=max_hops,
    )


def test_message_id_generator_is_repeatable() -> None:
    first = MessageIdGenerator(12345)
    second = MessageIdGenerator(12345)

    assert [first.next_id() for _ in range(3)] == [second.next_id() for _ in range(3)]


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


@pytest.mark.parametrize("ttl_seconds", [MIN_TTL_SECONDS - 1, MAX_TTL_SECONDS + 1])
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


def test_forwarded_copy_preserves_bounded_copy_mode() -> None:
    origin = StoredMessage.from_origin(make_message(), copies_left=4)

    forwarded = origin.forwarded_copy(at=10, copies_left=2)

    assert forwarded.copies_left == 2
    with pytest.raises(SimulationValidationError, match="copy-budget mode"):
        origin.forwarded_copy(at=10)


@pytest.mark.parametrize("copies_left", [0, 65, True])
def test_stored_message_rejects_invalid_copy_count(copies_left: object) -> None:
    with pytest.raises(SimulationValidationError, match="copies_left"):
        StoredMessage.from_origin(
            make_message(),
            copies_left=copies_left,  # type: ignore[arg-type]
        )


def test_node_updates_copy_budget_without_changing_storage_size() -> None:
    node = NodeState("alice")
    message = make_message()
    node.store_origin(message, copies_left=4)
    original = node.get_message(message.message_id)
    assert original is not None

    updated = node.update_copies_left(original, 2)

    assert updated.copies_left == 2
    assert node.message_count == 1
    assert node.stored_bytes == message.payload_size


def test_node_removes_expired_copy_and_updates_storage() -> None:
    node = NodeState("relay")
    message = make_message(ttl_seconds=60)
    node.store_origin(message)

    assert node.remove_expired(at=59) == ()
    removed = node.remove_expired(at=60)

    assert tuple(item.message for item in removed) == (message,)
    assert node.message_count == 0
    assert node.stored_bytes == 0


@pytest.mark.parametrize(
    ("arguments", "field_name"),
    [
        ({"max_messages": 0}, "max_messages"),
        ({"max_messages": 1_001}, "max_messages"),
        ({"max_bytes": 0}, "max_bytes"),
        ({"max_bytes": 64 * 1024 * 1024 + 1}, "max_bytes"),
        ({"max_messages": True}, "max_messages"),
    ],
)
def test_storage_quota_rejects_invalid_limits(
    arguments: dict[str, object], field_name: str
) -> None:
    with pytest.raises(SimulationValidationError, match=field_name):
        StorageQuota(**arguments)  # type: ignore[arg-type]


def test_fifo_eviction_removes_oldest_local_copy() -> None:
    node = NodeState("relay")
    quota = StorageQuota(max_messages=2, max_bytes=1_000)
    oldest = make_message(message_id="0" * 32, created_at=0)
    newer = make_message(message_id="1" * 32, created_at=1)
    incoming = make_message(message_id="2" * 32, created_at=2)

    node.store_origin_with_eviction(oldest, copies_left=None, quota=quota)
    node.store_origin_with_eviction(newer, copies_left=None, quota=quota)
    result = node.store_origin_with_eviction(incoming, copies_left=None, quota=quota)

    assert result.outcome is StoreOutcome.STORED
    assert tuple(item.message for item in result.evicted) == (oldest,)
    assert node.has_message(oldest.message_id) is False
    assert node.has_message(newer.message_id) is True
    assert node.has_message(incoming.message_id) is True
    assert node.message_count == 2


def test_fifo_eviction_uses_message_id_as_deterministic_tiebreaker() -> None:
    node = NodeState("relay")
    quota = StorageQuota(max_messages=2, max_bytes=1_000)
    high_id = make_message(message_id="f" * 32, created_at=0)
    low_id = make_message(message_id="0" * 32, created_at=0)
    incoming = make_message(message_id="1" * 32, created_at=1)
    node.store_origin_with_eviction(high_id, copies_left=None, quota=quota)
    node.store_origin_with_eviction(low_id, copies_left=None, quota=quota)

    result = node.store_origin_with_eviction(incoming, copies_left=None, quota=quota)

    assert tuple(item.message for item in result.evicted) == (low_id,)
    assert node.has_message(high_id.message_id) is True
    assert node.has_message(incoming.message_id) is True


def test_byte_quota_can_evict_multiple_copies_atomically() -> None:
    node = NodeState("relay")
    quota = StorageQuota(max_messages=10, max_bytes=200)
    first = make_message(message_id="0" * 32, payload_size=80, created_at=0)
    second = make_message(message_id="1" * 32, payload_size=80, created_at=1)
    incoming = make_message(message_id="2" * 32, payload_size=150, created_at=2)

    node.store_origin_with_eviction(first, copies_left=None, quota=quota)
    node.store_origin_with_eviction(second, copies_left=None, quota=quota)
    result = node.store_origin_with_eviction(incoming, copies_left=None, quota=quota)

    assert tuple(item.message for item in result.evicted) == (first, second)
    assert node.messages()[0].message == incoming
    assert node.message_count == 1
    assert node.stored_bytes == 150


def test_oversized_item_is_rejected_without_evicting_existing_copy() -> None:
    node = NodeState("relay")
    quota = StorageQuota(max_messages=2, max_bytes=200)
    existing = make_message(message_id="0" * 32, payload_size=80)
    oversized = make_message(message_id="1" * 32, payload_size=201)
    node.store_origin_with_eviction(existing, copies_left=None, quota=quota)

    result = node.store_origin_with_eviction(oversized, copies_left=None, quota=quota)

    assert result.outcome is StoreOutcome.ITEM_EXCEEDS_BYTE_QUOTA
    assert result.evicted == ()
    assert tuple(item.message for item in node.messages()) == (existing,)
    assert node.stored_bytes == 80


def test_duplicate_does_not_trigger_eviction() -> None:
    node = NodeState("relay")
    quota = StorageQuota(max_messages=1, max_bytes=128)
    message = make_message()
    node.store_origin_with_eviction(message, copies_left=None, quota=quota)

    result = node.store_origin_with_eviction(message, copies_left=None, quota=quota)

    assert result.outcome is StoreOutcome.DUPLICATE
    assert result.evicted == ()
    assert node.message_count == 1


def test_quota_holds_after_reproducible_sequence_of_varied_sizes() -> None:
    random_generator = random.Random(20_260_716)
    node = NodeState("relay")
    quota = StorageQuota(max_messages=7, max_bytes=500)

    for index in range(100):
        message = make_message(
            message_id=f"{index:032x}",
            created_at=index,
            payload_size=random_generator.randint(1, 200),
        )
        result = node.store_origin_with_eviction(message, copies_left=None, quota=quota)

        assert result.outcome is StoreOutcome.STORED
        assert node.message_count <= quota.max_messages
        assert node.stored_bytes <= quota.max_bytes
