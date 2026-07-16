# SPDX-License-Identifier: MPL-2.0

"""Command line entry point for reproducible simulator scenarios."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

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
    RoutingPolicy,
)
from lantern_sim.scenarios import DEFAULT_SEED, run_three_node_chain


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the deterministic three-node Lantern scenario."
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
        result = run_three_node_chain(
            policies[args.policy],
            seed=args.seed,
            payload_size=args.payload_size,
            ttl_seconds=args.ttl_seconds,
            max_hops=args.max_hops,
        )
    except (SimulationValidationError, SimulationLimitError) as error:
        parser.error(str(error))

    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
