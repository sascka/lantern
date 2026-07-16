# SPDX-License-Identifier: MPL-2.0

"""Command line entry point for reproducible simulator scenarios."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from lantern_sim.model import SimulationLimitError, SimulationValidationError
from lantern_sim.routing import DirectDelivery, EpidemicRouting, RoutingPolicy
from lantern_sim.scenarios import DEFAULT_SEED, run_three_node_chain


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the deterministic three-node Lantern scenario."
    )
    parser.add_argument(
        "--policy",
        choices=("direct", "epidemic"),
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    policies: dict[str, RoutingPolicy] = {
        "direct": DirectDelivery(),
        "epidemic": EpidemicRouting(),
    }

    try:
        result = run_three_node_chain(
            policies[args.policy],
            seed=args.seed,
            payload_size=args.payload_size,
        )
    except (SimulationValidationError, SimulationLimitError) as error:
        parser.error(str(error))

    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
