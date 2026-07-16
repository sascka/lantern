# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import pytest

from lantern_sim.faults import NetworkConditions
from lantern_sim.model import Encounter, SimulationValidationError
from lantern_sim.routing import BinarySprayAndWait, DirectDelivery, EpidemicRouting
from lantern_sim.scenarios import (
    MeshScenarioConfig,
    generate_uniform_contact_scenario,
    run_uniform_contact_scenario,
)


@pytest.mark.parametrize(
    ("arguments", "field_name"),
    [
        ({"node_count": 3}, "node_count"),
        ({"node_count": 51}, "node_count"),
        ({"message_count": 0}, "message_count"),
        ({"message_count": 101}, "message_count"),
        ({"node_count": 10, "encounter_count": 9}, "encounter_count"),
        ({"encounter_count": 10_001}, "encounter_count"),
        ({"node_count": True}, "node_count"),
    ],
)
def test_mesh_config_rejects_invalid_counts(
    arguments: dict[str, object], field_name: str
) -> None:
    with pytest.raises(SimulationValidationError, match=field_name):
        MeshScenarioConfig(**arguments)  # type: ignore[arg-type]


def test_mesh_generator_creates_bounded_valid_trace() -> None:
    config = MeshScenarioConfig(
        node_count=10,
        message_count=5,
        encounter_count=60,
        payload_size=128,
    )

    scenario = generate_uniform_contact_scenario(config, seed=42)

    assert len(scenario.node_ids) == 10
    assert len(scenario.messages) == 5
    assert len(scenario.encounters) == 60
    assert len(set(scenario.node_ids)) == 10
    assert all(item.source != item.destination for item in scenario.messages)
    assert all(item.left != item.right for item in scenario.encounters)
    assert scenario.encounters[:10] == tuple(
        Encounter(
            at=index + 1,
            left=f"node{index:03d}",
            right=f"node{(index + 1) % 10:03d}",
        )
        for index in range(10)
    )


def test_same_seed_creates_identical_trace() -> None:
    config = MeshScenarioConfig(node_count=10, message_count=5, encounter_count=60)

    first = generate_uniform_contact_scenario(config, seed=42)
    second = generate_uniform_contact_scenario(config, seed=42)

    assert first == second


def test_message_count_does_not_change_contact_trace() -> None:
    small = generate_uniform_contact_scenario(
        MeshScenarioConfig(
            node_count=10, message_count=1, encounter_count=60
        ),
        seed=42,
    )
    larger = generate_uniform_contact_scenario(
        MeshScenarioConfig(
            node_count=10, message_count=10, encounter_count=60
        ),
        seed=42,
    )

    assert small.node_ids == larger.node_ids
    assert small.encounters == larger.encounters


def test_all_policies_run_on_same_generated_scenario() -> None:
    config = MeshScenarioConfig(
        node_count=10,
        message_count=5,
        encounter_count=100,
        payload_size=128,
        ttl_seconds=300,
    )

    direct = run_uniform_contact_scenario(
        DirectDelivery(), config=config, seed=42
    )
    epidemic = run_uniform_contact_scenario(
        EpidemicRouting(), config=config, seed=42
    )
    spray = run_uniform_contact_scenario(
        BinarySprayAndWait(copy_budget=4), config=config, seed=42
    )

    assert direct.scenario_parameters == epidemic.scenario_parameters
    assert epidemic.scenario_parameters == spray.scenario_parameters
    assert direct.scenario == "uniform_contacts"
    assert direct.to_dict()["scenario_parameters"] == {
        "encounter_count": 100,
        "max_hops": 16,
        "message_count": 5,
        "node_count": 10,
        "payload_size": 128,
        "ttl_seconds": 300,
    }
    assert direct.node_count == epidemic.node_count == spray.node_count == 10
    assert (
        direct.message_count
        == epidemic.message_count
        == spray.message_count
        == 5
    )
    assert epidemic.delivered_count >= direct.delivered_count


def test_generated_faulty_run_is_repeatable() -> None:
    config = MeshScenarioConfig(node_count=10, message_count=5, encounter_count=60)
    conditions = NetworkConditions(
        loss_percent=20, duplicate_percent=10, reorder=True
    )

    first = run_uniform_contact_scenario(
        EpidemicRouting(),
        config=config,
        seed=42,
        network_conditions=conditions,
    )
    second = run_uniform_contact_scenario(
        EpidemicRouting(),
        config=config,
        seed=42,
        network_conditions=conditions,
    )

    assert first == second
    assert first.to_dict() == second.to_dict()
