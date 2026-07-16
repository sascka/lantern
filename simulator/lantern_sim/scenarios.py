# SPDX-License-Identifier: MPL-2.0

"""Small reproducible scenarios used by the CLI and tests."""

from __future__ import annotations

from lantern_sim.model import Encounter, Message, MessageIdGenerator
from lantern_sim.routing import RoutingPolicy
from lantern_sim.simulation import Simulation, SimulationResult

DEFAULT_SEED = 20_260_716


def run_three_node_chain(
    policy: RoutingPolicy,
    *,
    seed: int = DEFAULT_SEED,
    payload_size: int = 256,
) -> SimulationResult:
    """Run Alice -> Relay -> Bob with no direct Alice/Bob encounter."""

    id_generator = MessageIdGenerator(seed)
    message = Message(
        message_id=id_generator.next_id(),
        source="alice",
        destination="bob",
        created_at=0,
        payload_size=payload_size,
    )
    simulation = Simulation(
        node_ids=("alice", "relay", "bob"),
        messages=(message,),
        encounters=(
            Encounter(at=10, left="alice", right="relay"),
            Encounter(at=20, left="relay", right="bob"),
        ),
        seed=seed,
    )
    return simulation.run(policy)
