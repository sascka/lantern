# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import json

import pytest

from lantern_sim.batch import main
from lantern_sim.experiments import (
    MAX_BATCH_SCENARIOS,
    MAX_BATCH_SEEDS,
    AggregateResult,
    BatchExperimentConfig,
    run_batch_experiment,
)
from lantern_sim.faults import NetworkConditions
from lantern_sim.model import SimulationLimitError, SimulationValidationError
from lantern_sim.routing import BinarySprayAndWait, DirectDelivery, EpidemicRouting
from lantern_sim.scenarios import MeshScenarioConfig


def make_scenario(node_count: int = 4) -> MeshScenarioConfig:
    return MeshScenarioConfig(
        node_count=node_count,
        message_count=2,
        encounter_count=node_count * 2,
        payload_size=128,
    )


@pytest.mark.parametrize(
    ("scenarios", "seeds", "message"),
    [
        ((), (42,), "scenarios"),
        (
            tuple(
                make_scenario(index + 4)
                for index in range(MAX_BATCH_SCENARIOS + 1)
            ),
            (42,),
            "scenarios",
        ),
        ((make_scenario(), make_scenario()), (42,), "unique"),
        ((make_scenario(),), (), "seeds"),
        (
            (make_scenario(),),
            tuple(range(MAX_BATCH_SEEDS + 1)),
            "seeds",
        ),
        ((make_scenario(),), (42, 42), "unique"),
        ((make_scenario(),), (True,), "integer"),
        ((make_scenario(),), (-1,), "between"),
    ],
)
def test_batch_config_rejects_invalid_inputs(
    scenarios: tuple[MeshScenarioConfig, ...],
    seeds: tuple[int, ...],
    message: str,
) -> None:
    with pytest.raises(SimulationValidationError, match=message):
        BatchExperimentConfig(scenarios=scenarios, seeds=seeds)


def test_batch_run_count_has_hard_limit() -> None:
    config = BatchExperimentConfig(
        scenarios=tuple(
            make_scenario(index + 4) for index in range(MAX_BATCH_SCENARIOS)
        ),
        seeds=tuple(range(MAX_BATCH_SEEDS)),
    )

    with pytest.raises(SimulationLimitError, match="run count"):
        run_batch_experiment(
            config,
            (DirectDelivery(), EpidemicRouting()),
        )


def test_batch_rejects_empty_and_duplicate_policies() -> None:
    config = BatchExperimentConfig(scenarios=(make_scenario(),), seeds=(42,))

    with pytest.raises(SimulationValidationError, match="must not be empty"):
        run_batch_experiment(config, ())
    with pytest.raises(SimulationValidationError, match="unique"):
        run_batch_experiment(config, (DirectDelivery(), DirectDelivery()))


def test_batch_result_is_compact_aggregated_and_repeatable() -> None:
    config = BatchExperimentConfig(
        scenarios=(make_scenario(),),
        seeds=(42, 43),
    )
    policies = (
        DirectDelivery(),
        EpidemicRouting(),
        BinarySprayAndWait(copy_budget=4),
    )
    conditions = NetworkConditions(
        loss_percent=20,
        duplicate_percent=10,
        reorder=True,
    )

    first = run_batch_experiment(
        config,
        policies,
        network_conditions=conditions,
    )
    second = run_batch_experiment(
        config,
        policies,
        network_conditions=conditions,
    )

    assert first == second
    assert first.to_dict() == second.to_dict()
    assert len(first.runs) == 6
    assert len(first.aggregates) == 3
    assert all(item.run_count == 2 for item in first.aggregates)
    assert sum(item.run_count for item in first.aggregates) == len(first.runs)
    serialized_runs = first.to_dict()["runs"]
    assert isinstance(serialized_runs, list)
    assert all("attempts" not in item for item in serialized_runs)
    assert all("deliveries" not in item for item in serialized_runs)


def test_aggregate_uses_all_deliveries_instead_of_averaging_run_averages() -> None:
    config = BatchExperimentConfig(
        scenarios=(make_scenario(),),
        seeds=(42, 43, 44),
    )
    result = run_batch_experiment(config, (EpidemicRouting(),))
    aggregate = result.aggregates[0]

    assert aggregate.total_messages == sum(
        item.message_count for item in result.runs
    )
    assert aggregate.total_delivered == sum(
        item.delivered_count for item in result.runs
    )
    assert aggregate.total_delivery_delay == sum(
        item.total_delivery_delay for item in result.runs
    )
    assert aggregate.average_delivery_delay == (
        aggregate.total_delivery_delay / aggregate.total_delivered
    )


def test_aggregate_rejects_empty_run_list() -> None:
    with pytest.raises(SimulationValidationError, match="empty"):
        AggregateResult.from_runs(())


def test_batch_cli_outputs_parseable_json(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        [
            "--seeds",
            "42,43",
            "--nodes",
            "4",
            "--messages",
            "2",
            "--encounters-per-node",
            "2",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert output["format_version"] == 1
    assert output["spdx_license"] == "MPL-2.0"
    assert output["seeds"] == [42, 43]
    assert output["run_count"] == 6
    assert len(output["aggregates"]) == 3


def test_batch_cli_rejects_invalid_node_count() -> None:
    with pytest.raises(SystemExit) as error:
        main(["--nodes", "3"])

    assert error.value.code == 2
