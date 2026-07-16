# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import pytest

from lantern_sim.faults import NetworkConditions
from lantern_sim.model import (
    Encounter,
    Message,
    MessageIdGenerator,
    SimulationValidationError,
)
from lantern_sim.routing import BinarySprayAndWait, DirectDelivery, EpidemicRouting
from lantern_sim.scenarios import run_three_node_chain
from lantern_sim.simulation import (
    AttemptOutcome,
    BlockReason,
    RemovalReason,
    Simulation,
)


def make_message(
    *,
    message_id: str | None = None,
    created_at: int = 0,
    payload_size: int = 128,
    ttl_seconds: int = 300,
    max_hops: int = 16,
) -> Message:
    return Message(
        message_id=message_id or MessageIdGenerator(42).next_id(),
        source="alice",
        destination="bob",
        created_at=created_at,
        payload_size=payload_size,
        ttl_seconds=ttl_seconds,
        max_hops=max_hops,
    )


def test_epidemic_delivers_through_relay() -> None:
    result = run_three_node_chain(EpidemicRouting(), seed=42, payload_size=128)

    assert result.delivered_count == 1
    assert result.delivery_rate == 1.0
    assert result.average_delivery_delay == 20.0
    assert result.transmission_count == 2
    assert result.bytes_transmitted == 256
    assert result.peak_stored_messages == 3
    assert result.peak_stored_bytes == 384
    assert [item.sender for item in result.transmissions] == ["alice", "relay"]
    assert [item.receiver for item in result.transmissions] == ["relay", "bob"]
    assert [item.remaining_ttl for item in result.transmissions] == [290, 280]
    assert [item.hops_taken for item in result.transmissions] == [1, 2]
    assert result.removals == ()
    assert result.blocked_transfers == ()


def test_direct_delivery_does_not_give_message_to_relay() -> None:
    result = run_three_node_chain(DirectDelivery(), seed=42, payload_size=128)

    assert result.delivered_count == 0
    assert result.delivery_rate == 0.0
    assert result.average_delivery_delay is None
    assert result.transmission_count == 0
    assert result.peak_stored_messages == 1
    assert result.peak_stored_bytes == 128


def test_direct_delivery_succeeds_when_alice_meets_bob() -> None:
    simulation = Simulation(
        node_ids=("alice", "bob"),
        messages=(make_message(),),
        encounters=(Encounter(at=15, left="alice", right="bob"),),
        seed=42,
    )

    result = simulation.run(DirectDelivery())

    assert result.delivered_count == 1
    assert result.average_delivery_delay == 15.0
    assert result.transmission_count == 1


def test_repeated_encounters_do_not_create_duplicate_transmissions() -> None:
    simulation = Simulation(
        node_ids=("alice", "relay", "bob"),
        messages=(make_message(),),
        encounters=(
            Encounter(at=10, left="alice", right="relay"),
            Encounter(at=20, left="relay", right="bob"),
            Encounter(at=30, left="alice", right="relay"),
            Encounter(at=40, left="relay", right="bob"),
        ),
        seed=42,
    )

    result = simulation.run(EpidemicRouting())

    assert result.delivered_count == 1
    assert result.transmission_count == 2


def test_encounter_before_message_creation_does_not_transfer_future_message() -> None:
    simulation = Simulation(
        node_ids=("alice", "relay", "bob"),
        messages=(make_message(created_at=10),),
        encounters=(
            Encounter(at=5, left="alice", right="relay"),
            Encounter(at=20, left="relay", right="bob"),
        ),
        seed=42,
    )

    result = simulation.run(EpidemicRouting())

    assert result.delivered_count == 0
    assert result.transmission_count == 0


def test_creation_precedes_encounter_at_same_time() -> None:
    simulation = Simulation(
        node_ids=("alice", "bob"),
        messages=(make_message(created_at=10),),
        encounters=(Encounter(at=10, left="alice", right="bob"),),
        seed=42,
    )

    result = simulation.run(DirectDelivery())

    assert result.delivered_count == 1
    assert result.average_delivery_delay == 0.0


def test_simulation_rejects_unknown_encounter_node() -> None:
    with pytest.raises(SimulationValidationError, match="unknown encounter node"):
        Simulation(
            node_ids=("alice", "bob"),
            messages=(make_message(),),
            encounters=(Encounter(at=10, left="alice", right="mallory"),),
            seed=42,
        )


def test_repeated_runs_are_identical() -> None:
    first = run_three_node_chain(EpidemicRouting(), seed=20260716)
    second = run_three_node_chain(EpidemicRouting(), seed=20260716)

    assert first == second
    assert first.to_dict() == second.to_dict()


def test_ttl_expires_on_all_nodes_before_late_encounter() -> None:
    simulation = Simulation(
        node_ids=("alice", "relay", "bob"),
        messages=(make_message(ttl_seconds=60),),
        encounters=(
            Encounter(at=10, left="alice", right="relay"),
            Encounter(at=60, left="relay", right="bob"),
        ),
        seed=42,
    )

    result = simulation.run(EpidemicRouting())

    assert result.delivered_count == 0
    assert result.transmission_count == 1
    assert [(item.node_id, item.reason) for item in result.removals] == [
        ("alice", RemovalReason.TTL_EXPIRED),
        ("relay", RemovalReason.TTL_EXPIRED),
    ]


def test_one_hop_budget_blocks_transfer_to_non_destination() -> None:
    result = run_three_node_chain(
        EpidemicRouting(), seed=42, payload_size=128, max_hops=1
    )

    assert result.delivered_count == 0
    assert result.transmission_count == 0
    assert len(result.blocked_transfers) == 1
    assert (
        result.blocked_transfers[0].reason
        is BlockReason.HOP_LIMIT_BEFORE_DESTINATION
    )
    assert result.blocked_transfers[0].sender == "alice"
    assert result.blocked_transfers[0].receiver == "relay"


def test_one_hop_budget_allows_direct_delivery() -> None:
    simulation = Simulation(
        node_ids=("alice", "bob"),
        messages=(make_message(max_hops=1),),
        encounters=(Encounter(at=10, left="alice", right="bob"),),
        seed=42,
    )

    result = simulation.run(EpidemicRouting())

    assert result.delivered_count == 1
    assert result.transmission_count == 1
    assert result.transmissions[0].hops_taken == 1
    assert result.blocked_transfers == ()


def test_two_hop_budget_allows_chain_delivery() -> None:
    result = run_three_node_chain(
        EpidemicRouting(), seed=42, payload_size=128, max_hops=2
    )

    assert result.delivered_count == 1
    assert result.transmission_count == 2
    assert result.transmissions[-1].hops_taken == 2


def test_copy_at_hop_limit_cannot_spread_past_destination() -> None:
    simulation = Simulation(
        node_ids=("alice", "bob", "carol"),
        messages=(make_message(max_hops=1),),
        encounters=(
            Encounter(at=10, left="alice", right="bob"),
            Encounter(at=20, left="bob", right="carol"),
        ),
        seed=42,
    )

    result = simulation.run(EpidemicRouting())

    assert result.delivered_count == 1
    assert result.transmission_count == 1
    assert len(result.blocked_transfers) == 1
    assert result.blocked_transfers[0].reason is BlockReason.HOP_LIMIT_EXCEEDED
    assert result.blocked_transfers[0].sender == "bob"
    assert result.blocked_transfers[0].receiver == "carol"


def test_result_serializes_expiration_and_hop_block_reasons() -> None:
    blocked = run_three_node_chain(
        EpidemicRouting(), seed=42, payload_size=128, max_hops=1
    ).to_dict()

    assert blocked["blocked_transfer_count"] == 1
    assert blocked["blocked_transfers"][0]["reason"] == (
        "hop_limit_before_destination"
    )


def test_spray_and_wait_delivers_chain_with_two_copy_tokens() -> None:
    result = run_three_node_chain(
        BinarySprayAndWait(copy_budget=2), seed=42, payload_size=128
    )

    assert result.delivered_count == 1
    assert result.transmission_count == 2
    assert result.peak_stored_messages == 2
    assert result.policy_parameters == (("copy_budget", 2),)
    assert [item.sender_copies_left_after for item in result.transmissions] == [
        1,
        0,
    ]
    assert [item.receiver_copies_left for item in result.transmissions] == [1, 1]


def test_spray_and_wait_with_one_token_cannot_use_relay() -> None:
    result = run_three_node_chain(
        BinarySprayAndWait(copy_budget=1), seed=42, payload_size=128
    )

    assert result.delivered_count == 0
    assert result.transmission_count == 0
    assert result.peak_stored_messages == 1


def test_blocked_hop_does_not_consume_spray_copy_tokens() -> None:
    simulation = Simulation(
        node_ids=("alice", "relay", "bob"),
        messages=(make_message(max_hops=1),),
        encounters=(
            Encounter(at=10, left="alice", right="relay"),
            Encounter(at=20, left="alice", right="bob"),
        ),
        seed=42,
    )

    result = simulation.run(BinarySprayAndWait(copy_budget=2))

    assert result.delivered_count == 1
    assert result.transmission_count == 1
    assert len(result.blocked_transfers) == 1
    assert result.transmissions[0].sender_copies_left_after == 1
    assert result.transmissions[0].receiver_copies_left == 1


def test_binary_spray_never_exceeds_copy_budget() -> None:
    simulation = Simulation(
        node_ids=("alice", "relay1", "relay2", "relay3", "bob"),
        messages=(make_message(),),
        encounters=(
            Encounter(at=10, left="alice", right="relay1"),
            Encounter(at=20, left="alice", right="relay2"),
            Encounter(at=30, left="relay1", right="relay3"),
            Encounter(at=40, left="relay3", right="bob"),
        ),
        seed=42,
    )

    result = simulation.run(BinarySprayAndWait(copy_budget=4))

    assert result.delivered_count == 1
    assert result.transmission_count == 4
    assert result.peak_stored_messages == 4
    assert result.peak_stored_bytes == 4 * 128
    assert all(
        item.receiver_copies_left is not None for item in result.transmissions
    )


def test_result_serializes_spray_policy_parameters() -> None:
    result = run_three_node_chain(BinarySprayAndWait(copy_budget=2), seed=42)

    serialized = result.to_dict()

    assert serialized["policy"] == "spray_and_wait"
    assert serialized["policy_parameters"] == {"copy_budget": 2}


def test_total_loss_records_attempt_without_storing_copy() -> None:
    result = run_three_node_chain(
        EpidemicRouting(),
        seed=42,
        payload_size=128,
        network_conditions=NetworkConditions(loss_percent=100),
    )

    assert result.delivered_count == 0
    assert result.attempt_count == 1
    assert result.transmission_count == 0
    assert result.lost_attempt_count == 1
    assert result.bytes_attempted == 128
    assert result.bytes_transmitted == 0
    assert result.attempts[0].outcome is AttemptOutcome.LOST
    assert result.to_dict()["network_conditions"] == {
        "duplicate_percent": 0,
        "loss_percent": 100,
        "reorder": False,
    }


def test_duplicate_transfer_is_counted_but_not_stored_twice() -> None:
    result = run_three_node_chain(
        EpidemicRouting(),
        seed=42,
        payload_size=128,
        network_conditions=NetworkConditions(duplicate_percent=100),
    )

    assert result.delivered_count == 1
    assert result.attempt_count == 4
    assert result.transmission_count == 2
    assert result.duplicate_attempt_count == 2
    assert result.bytes_attempted == 4 * 128
    assert result.bytes_transmitted == 2 * 128
    assert result.peak_stored_messages == 3


def test_duplicate_does_not_consume_extra_spray_tokens() -> None:
    result = run_three_node_chain(
        BinarySprayAndWait(copy_budget=2),
        seed=42,
        payload_size=128,
        network_conditions=NetworkConditions(duplicate_percent=100),
    )

    assert result.delivered_count == 1
    assert result.attempt_count == 4
    assert result.transmission_count == 2
    assert result.peak_stored_messages == 2
    assert [item.sender_copies_left_after for item in result.transmissions] == [
        1,
        0,
    ]


def test_reordered_batch_delivers_all_messages_in_reverse_order() -> None:
    low_id = "0" * 32
    high_id = "f" * 32
    simulation = Simulation(
        node_ids=("alice", "bob"),
        messages=(
            make_message(message_id=low_id),
            make_message(message_id=high_id),
        ),
        encounters=(Encounter(at=10, left="alice", right="bob"),),
        seed=42,
    )

    result = simulation.run(
        DirectDelivery(), NetworkConditions(reorder=True)
    )

    assert result.delivered_count == 2
    assert [item.message_id for item in result.transmissions] == [high_id, low_id]
    assert [item.outcome for item in result.attempts] == [
        AttemptOutcome.STORED,
        AttemptOutcome.STORED,
    ]


def test_retry_after_loss_preserves_spray_copy_budget() -> None:
    simulation = Simulation(
        node_ids=("alice", "relay", "bob"),
        messages=(make_message(message_id="0" * 32),),
        encounters=(
            Encounter(at=10, left="alice", right="relay"),
            Encounter(at=20, left="alice", right="bob"),
        ),
        seed=4,
    )

    result = simulation.run(
        BinarySprayAndWait(copy_budget=2),
        NetworkConditions(loss_percent=50),
    )

    assert result.delivered_count == 1
    assert [item.outcome for item in result.attempts] == [
        AttemptOutcome.LOST,
        AttemptOutcome.STORED,
    ]
    assert result.transmissions[0].sender_copies_left_after == 1
    assert result.transmissions[0].receiver_copies_left == 1


def test_repeated_faulty_runs_are_identical() -> None:
    conditions = NetworkConditions(
        loss_percent=20, duplicate_percent=10, reorder=True
    )

    first = run_three_node_chain(
        EpidemicRouting(), seed=20260716, network_conditions=conditions
    )
    second = run_three_node_chain(
        EpidemicRouting(), seed=20260716, network_conditions=conditions
    )

    assert first == second
    assert first.to_dict() == second.to_dict()
