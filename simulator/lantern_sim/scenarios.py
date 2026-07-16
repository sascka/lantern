# SPDX-License-Identifier: MPL-2.0

"""Small reproducible scenarios used by the CLI and tests."""

from __future__ import annotations

from lantern_sim.faults import NetworkConditions
from lantern_sim.model import (
    DEFAULT_MAX_HOPS,
    DEFAULT_TTL_SECONDS,
    Encounter,
    Message,
    MessageIdGenerator,
    StorageQuota,
)
from lantern_sim.routing import RoutingPolicy
from lantern_sim.simulation import Simulation, SimulationResult

DEFAULT_SEED = 20_260_716


def run_three_node_chain(
    policy: RoutingPolicy,
    *,
    seed: int = DEFAULT_SEED,
    payload_size: int = 256,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    max_hops: int = DEFAULT_MAX_HOPS,
    network_conditions: NetworkConditions | None = None,
    storage_quota: StorageQuota | None = None,
) -> SimulationResult:
    """Run Alice -> Relay -> Bob with no direct Alice/Bob encounter."""

    id_generator = MessageIdGenerator(seed)
    message = Message(
        message_id=id_generator.next_id(),
        source="alice",
        destination="bob",
        created_at=0,
        payload_size=payload_size,
        ttl_seconds=ttl_seconds,
        max_hops=max_hops,
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
    return simulation.run(
        policy,
        network_conditions=network_conditions,
        storage_quota=storage_quota,
    )
