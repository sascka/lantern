# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import pytest

from lantern_sim.faults import NetworkConditions
from lantern_sim.model import Encounter, SimulationValidationError
from lantern_sim.routing import BinarySprayAndWait, DirectDelivery, EpidemicRouting
from lantern_sim.scenarios import (
    ContactRoundScenarioConfig,
    MeshScenarioConfig,
    generate_contact_round_scenario,
    generate_uniform_contact_scenario,
    run_configured_scenario,
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
        MeshScenarioConfig(node_count=10, message_count=1, encounter_count=60),
        seed=42,
    )
    larger = generate_uniform_contact_scenario(
        MeshScenarioConfig(node_count=10, message_count=10, encounter_count=60),
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

    direct = run_uniform_contact_scenario(DirectDelivery(), config=config, seed=42)
    epidemic = run_uniform_contact_scenario(EpidemicRouting(), config=config, seed=42)
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
    assert direct.message_count == epidemic.message_count == spray.message_count == 5
    assert epidemic.delivered_count >= direct.delivered_count


def test_generated_faulty_run_is_repeatable() -> None:
    config = MeshScenarioConfig(node_count=10, message_count=5, encounter_count=60)
    conditions = NetworkConditions(loss_percent=20, duplicate_percent=10, reorder=True)

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


@pytest.mark.parametrize(
    ("arguments", "field_name"),
    [
        ({"node_count": 3}, "node_count"),
        ({"node_count": 201}, "node_count"),
        ({"round_count": 0}, "round_count"),
        ({"round_count": 101}, "round_count"),
        ({"round_count": True}, "round_count"),
    ],
)
def test_round_config_rejects_invalid_counts(
    arguments: dict[str, object], field_name: str
) -> None:
    with pytest.raises(SimulationValidationError, match=field_name):
        ContactRoundScenarioConfig(**arguments)  # type: ignore[arg-type]


def test_round_scenario_pairs_each_even_node_once_per_round() -> None:
    config = ContactRoundScenarioConfig(
        node_count=10,
        message_count=5,
        round_count=6,
        payload_size=128,
    )

    scenario = generate_contact_round_scenario(config, seed=42)

    assert len(scenario.node_ids) == 10
    assert len(scenario.messages) == 5
    assert len(scenario.encounters) == 30
    for round_number in range(1, 7):
        round_encounters = tuple(
            item for item in scenario.encounters if item.at == round_number
        )
        participants = tuple(
            node_id for item in round_encounters for node_id in (item.left, item.right)
        )
        assert len(round_encounters) == 5
        assert len(participants) == len(set(participants)) == 10


def test_round_scenario_supports_two_hundred_nodes() -> None:
    config = ContactRoundScenarioConfig(
        node_count=200,
        message_count=10,
        round_count=100,
    )

    scenario = generate_contact_round_scenario(config, seed=42)

    assert len(scenario.node_ids) == 200
    assert len(scenario.encounters) == 10_000
    assert scenario.parameters == config.parameters()


def test_round_messages_do_not_change_contact_trace() -> None:
    small = generate_contact_round_scenario(
        ContactRoundScenarioConfig(
            node_count=20,
            message_count=1,
            round_count=10,
        ),
        seed=42,
    )
    larger = generate_contact_round_scenario(
        ContactRoundScenarioConfig(
            node_count=20,
            message_count=10,
            round_count=10,
        ),
        seed=42,
    )

    assert small.encounters == larger.encounters


def test_all_policies_run_on_one_hundred_node_round_scenario() -> None:
    config = ContactRoundScenarioConfig(
        node_count=100,
        message_count=5,
        round_count=10,
        payload_size=128,
    )

    results = tuple(
        run_configured_scenario(policy, config=config, seed=42)
        for policy in (
            DirectDelivery(),
            EpidemicRouting(),
            BinarySprayAndWait(copy_budget=8),
        )
    )

    assert all(item.scenario == "uniform_contact_rounds" for item in results)
    assert all(item.node_count == 100 for item in results)
    assert all(item.message_count == 5 for item in results)
