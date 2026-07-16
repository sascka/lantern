# SPDX-License-Identifier: MPL-2.0

"""Command line entry point for bounded batch experiments."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from lantern_sim.experiments import BatchExperimentConfig, run_batch_experiment
from lantern_sim.faults import NetworkConditions
from lantern_sim.model import (
    DEFAULT_COPY_BUDGET,
    DEFAULT_MAX_HOPS,
    DEFAULT_TTL_SECONDS,
    SimulationLimitError,
    SimulationValidationError,
)
from lantern_sim.routing import (
    BinarySprayAndWait,
    DirectDelivery,
    EpidemicRouting,
)
from lantern_sim.scenarios import ContactRoundScenarioConfig, MeshScenarioConfig

DEFAULT_BATCH_SEEDS = (20_260_716, 20_260_717, 20_260_718)
DEFAULT_BATCH_NODES = (20, 50)


def _parse_integer_list(value: str) -> tuple[int, ...]:
    parts = value.split(",")
    if not parts or any(not item.strip() for item in parts):
        raise argparse.ArgumentTypeError("expected comma-separated integers")
    try:
        return tuple(int(item.strip()) for item in parts)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected comma-separated integers") from error


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a bounded batch of Lantern routing experiments."
    )
    parser.add_argument(
        "--contact-model",
        choices=("sequential", "rounds"),
        default="sequential",
        help="legacy sequential contacts or size-comparable contact rounds",
    )
    parser.add_argument(
        "--seeds",
        type=_parse_integer_list,
        default=DEFAULT_BATCH_SEEDS,
        help="comma-separated deterministic experiment seeds",
    )
    parser.add_argument(
        "--nodes",
        type=_parse_integer_list,
        default=DEFAULT_BATCH_NODES,
        help="comma-separated node counts",
    )
    parser.add_argument(
        "--messages",
        type=int,
        default=10,
        help="message count in each generated scenario",
    )
    parser.add_argument(
        "--encounters-per-node",
        type=int,
        default=10,
        help="encounter count multiplier for each node count",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=40,
        help="contact round count for the rounds model",
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=256,
        help="opaque simulated payload size in bytes",
    )
    parser.add_argument(
        "--ttl-seconds",
        type=int,
        default=DEFAULT_TTL_SECONDS,
        help="message lifetime requested by the source",
    )
    parser.add_argument(
        "--max-hops",
        type=int,
        default=DEFAULT_MAX_HOPS,
        help="maximum number of sequential transmissions",
    )
    copy_budget_group = parser.add_mutually_exclusive_group()
    copy_budget_group.add_argument(
        "--copy-budget",
        type=int,
        help="one initial Spray-and-Wait copy-token budget",
    )
    copy_budget_group.add_argument(
        "--copy-budgets",
        type=_parse_integer_list,
        help="comma-separated Spray-and-Wait copy-token budgets",
    )
    parser.add_argument(
        "--loss-percent",
        type=int,
        default=0,
        help="deterministic percentage of transfer attempts to lose",
    )
    parser.add_argument(
        "--duplicate-percent",
        type=int,
        default=0,
        help="deterministic percentage of stored transfers to duplicate",
    )
    parser.add_argument(
        "--reorder",
        action="store_true",
        help="reverse message batches selected during an encounter",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.contact_model == "sequential":
            scenarios = tuple(
                MeshScenarioConfig(
                    node_count=node_count,
                    message_count=args.messages,
                    encounter_count=node_count * args.encounters_per_node,
                    payload_size=args.payload_size,
                    ttl_seconds=args.ttl_seconds,
                    max_hops=args.max_hops,
                )
                for node_count in args.nodes
            )
        else:
            scenarios = tuple(
                ContactRoundScenarioConfig(
                    node_count=node_count,
                    message_count=args.messages,
                    round_count=args.rounds,
                    payload_size=args.payload_size,
                    ttl_seconds=args.ttl_seconds,
                    max_hops=args.max_hops,
                )
                for node_count in args.nodes
            )
        config = BatchExperimentConfig(
            scenarios=scenarios,
            seeds=args.seeds,
        )
        copy_budgets = args.copy_budgets
        if copy_budgets is None:
            copy_budgets = (
                args.copy_budget
                if args.copy_budget is not None
                else DEFAULT_COPY_BUDGET,
            )
        policies = (
            DirectDelivery(),
            EpidemicRouting(),
            *(BinarySprayAndWait(item) for item in copy_budgets),
        )
        result = run_batch_experiment(
            config,
            policies,
            network_conditions=NetworkConditions(
                loss_percent=args.loss_percent,
                duplicate_percent=args.duplicate_percent,
                reorder=args.reorder,
            ),
        )
    except (SimulationValidationError, SimulationLimitError) as error:
        parser.error(str(error))

    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
