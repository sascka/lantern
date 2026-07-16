# SPDX-License-Identifier: MPL-2.0

"""Command line entry point for reproducible simulator scenarios."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from lantern_sim.faults import NetworkConditions
from lantern_sim.model import (
    DEFAULT_COPY_BUDGET,
    DEFAULT_MAX_HOPS,
    DEFAULT_TTL_SECONDS,
    MAX_STORED_BYTES_PER_NODE,
    MAX_STORED_MESSAGES_PER_NODE,
    SimulationLimitError,
    SimulationValidationError,
    StorageQuota,
)
from lantern_sim.routing import (
    BinarySprayAndWait,
    DirectDelivery,
    EpidemicRouting,
    RoutingPolicy,
)
from lantern_sim.scenarios import (
    DEFAULT_SEED,
    MeshScenarioConfig,
    run_three_node_chain,
    run_uniform_contact_scenario,
)
from lantern_sim.tombstones import (
    DEFAULT_MAX_TOMBSTONES,
    DEFAULT_TOMBSTONE_RETENTION_SECONDS,
    TombstoneConfig,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a deterministic Lantern routing scenario."
    )
    parser.add_argument(
        "--scenario",
        choices=("chain", "mesh"),
        default="chain",
        help="three-node chain or bounded synthetic contact trace",
    )
    parser.add_argument(
        "--policy",
        choices=("direct", "epidemic", "spray"),
        default="epidemic",
        help="routing policy to compare",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="deterministic unsigned 64-bit experiment seed",
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
    parser.add_argument(
        "--copy-budget",
        type=int,
        default=DEFAULT_COPY_BUDGET,
        help="initial copy-token budget for Spray-and-Wait",
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
        help="reverse each batch of messages selected during an encounter",
    )
    parser.add_argument(
        "--max-stored-messages",
        type=int,
        default=MAX_STORED_MESSAGES_PER_NODE,
        help="maximum stored copies per simulated node",
    )
    parser.add_argument(
        "--max-stored-bytes",
        type=int,
        default=MAX_STORED_BYTES_PER_NODE,
        help="maximum bytes of stored copies per simulated node",
    )
    parser.add_argument(
        "--max-tombstones",
        type=int,
        default=DEFAULT_MAX_TOMBSTONES,
        help="maximum recent removed IDs remembered per simulated node",
    )
    parser.add_argument(
        "--tombstone-retention-seconds",
        type=int,
        default=DEFAULT_TOMBSTONE_RETENTION_SECONDS,
        help="how long a removed message ID remains blocked",
    )
    parser.add_argument(
        "--nodes",
        type=int,
        default=20,
        help="node count for the mesh scenario",
    )
    parser.add_argument(
        "--messages",
        type=int,
        default=10,
        help="generated message count for the mesh scenario",
    )
    parser.add_argument(
        "--encounters",
        type=int,
        default=200,
        help="generated encounter count for the mesh scenario",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="omit detailed event arrays from JSON output",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        policies: dict[str, RoutingPolicy] = {
            "direct": DirectDelivery(),
            "epidemic": EpidemicRouting(),
            "spray": BinarySprayAndWait(args.copy_budget),
        }
        network_conditions = NetworkConditions(
            loss_percent=args.loss_percent,
            duplicate_percent=args.duplicate_percent,
            reorder=args.reorder,
        )
        storage_quota = StorageQuota(
            max_messages=args.max_stored_messages,
            max_bytes=args.max_stored_bytes,
        )
        tombstone_config = TombstoneConfig(
            max_entries=args.max_tombstones,
            retention_seconds=args.tombstone_retention_seconds,
        )
        if args.scenario == "chain":
            result = run_three_node_chain(
                policies[args.policy],
                seed=args.seed,
                payload_size=args.payload_size,
                ttl_seconds=args.ttl_seconds,
                max_hops=args.max_hops,
                network_conditions=network_conditions,
                storage_quota=storage_quota,
                tombstone_config=tombstone_config,
            )
        else:
            scenario_config = MeshScenarioConfig(
                node_count=args.nodes,
                message_count=args.messages,
                encounter_count=args.encounters,
                payload_size=args.payload_size,
                ttl_seconds=args.ttl_seconds,
                max_hops=args.max_hops,
            )
            result = run_uniform_contact_scenario(
                policies[args.policy],
                config=scenario_config,
                seed=args.seed,
                network_conditions=network_conditions,
                storage_quota=storage_quota,
                tombstone_config=tombstone_config,
            )
    except (SimulationValidationError, SimulationLimitError) as error:
        parser.error(str(error))

    serialized = result.to_dict()
    if args.summary:
        for field_name in (
            "attempts",
            "blocked_transfers",
            "deliveries",
            "removals",
            "storage_rejections",
            "tombstone_events",
            "tombstone_rejections",
            "transmissions",
        ):
            serialized.pop(field_name)
    print(json.dumps(serialized, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
