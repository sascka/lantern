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
from lantern_sim.simulation import Simulation


def make_message(*, created_at: int = 0, payload_size: int = 128) -> Message:
    return Message(
        message_id=MessageIdGenerator(42).next_id(),
        source="alice",
        destination="bob",
        created_at=created_at,
        payload_size=payload_size,
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
