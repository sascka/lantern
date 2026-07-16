# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import pytest

from lantern_sim.model import (
    Encounter,
    Message,
    MessageIdGenerator,
    SimulationValidationError,
)
from lantern_sim.routing import DirectDelivery, EpidemicRouting
from lantern_sim.scenarios import run_three_node_chain
from lantern_sim.simulation import BlockReason, RemovalReason, Simulation


def make_message(
    *,
    created_at: int = 0,
    payload_size: int = 128,
    ttl_seconds: int = 300,
    max_hops: int = 16,
) -> Message:
    return Message(
        message_id=MessageIdGenerator(42).next_id(),
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
