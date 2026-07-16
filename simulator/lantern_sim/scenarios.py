# SPDX-License-Identifier: MPL-2.0

"""Small reproducible scenarios used by the CLI and tests."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import TypeAlias

from lantern_sim.faults import NetworkConditions
from lantern_sim.model import (
    DEFAULT_MAX_HOPS,
    DEFAULT_TTL_SECONDS,
    Encounter,
    Message,
    MessageIdGenerator,
    SimulationValidationError,
    StorageQuota,
)
from lantern_sim.routing import RoutingPolicy
from lantern_sim.simulation import Simulation, SimulationResult
from lantern_sim.tombstones import TombstoneConfig

DEFAULT_SEED = 20_260_716
MIN_MESH_NODES = 4
MAX_MESH_NODES = 50
MAX_MESH_MESSAGES = 100
MAX_MESH_ENCOUNTERS = 10_000
MAX_ROUND_NODES = 200
MAX_CONTACT_ROUNDS = 100


def _validate_count(value: int, *, field_name: str, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SimulationValidationError(f"{field_name} must be an integer")
    if not minimum <= value <= maximum:
        raise SimulationValidationError(
            f"{field_name} must be between {minimum} and {maximum}"
        )


@dataclass(frozen=True, slots=True)
class MeshScenarioConfig:
    node_count: int = 20
    message_count: int = 10
    encounter_count: int = 200
    payload_size: int = 256
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    max_hops: int = DEFAULT_MAX_HOPS

    def __post_init__(self) -> None:
        _validate_count(
            self.node_count,
            field_name="node_count",
            minimum=MIN_MESH_NODES,
            maximum=MAX_MESH_NODES,
        )
        _validate_count(
            self.message_count,
            field_name="message_count",
            minimum=1,
            maximum=MAX_MESH_MESSAGES,
        )
        _validate_count(
            self.encounter_count,
            field_name="encounter_count",
            minimum=self.node_count,
            maximum=MAX_MESH_ENCOUNTERS,
        )

        Message(
            message_id="0" * 32,
            source="source",
            destination="destination",
            created_at=0,
            payload_size=self.payload_size,
            ttl_seconds=self.ttl_seconds,
            max_hops=self.max_hops,
        )

    def parameters(self) -> tuple[tuple[str, int], ...]:
        return (
            ("encounter_count", self.encounter_count),
            ("max_hops", self.max_hops),
            ("message_count", self.message_count),
            ("node_count", self.node_count),
            ("payload_size", self.payload_size),
            ("ttl_seconds", self.ttl_seconds),
        )


@dataclass(frozen=True, slots=True)
class ContactRoundScenarioConfig:
    node_count: int = 20
    message_count: int = 10
    round_count: int = 40
    payload_size: int = 256
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    max_hops: int = DEFAULT_MAX_HOPS

    def __post_init__(self) -> None:
        _validate_count(
            self.node_count,
            field_name="node_count",
            minimum=MIN_MESH_NODES,
            maximum=MAX_ROUND_NODES,
        )
        _validate_count(
            self.message_count,
            field_name="message_count",
            minimum=1,
            maximum=MAX_MESH_MESSAGES,
        )
        _validate_count(
            self.round_count,
            field_name="round_count",
            minimum=1,
            maximum=MAX_CONTACT_ROUNDS,
        )

        Message(
            message_id="0" * 32,
            source="source",
            destination="destination",
            created_at=0,
            payload_size=self.payload_size,
            ttl_seconds=self.ttl_seconds,
            max_hops=self.max_hops,
        )

    @property
    def encounter_count(self) -> int:
        return self.round_count * (self.node_count // 2)

    def parameters(self) -> tuple[tuple[str, int], ...]:
        return (
            ("encounter_count", self.encounter_count),
            ("max_hops", self.max_hops),
            ("message_count", self.message_count),
            ("node_count", self.node_count),
            ("payload_size", self.payload_size),
            ("round_count", self.round_count),
            ("ttl_seconds", self.ttl_seconds),
        )


ScenarioConfig: TypeAlias = MeshScenarioConfig | ContactRoundScenarioConfig


def configured_scenario_name(config: ScenarioConfig) -> str:
    if isinstance(config, MeshScenarioConfig):
        return "uniform_contacts"
    if isinstance(config, ContactRoundScenarioConfig):
        return "uniform_contact_rounds"
    raise SimulationValidationError("unsupported scenario configuration")


@dataclass(frozen=True, slots=True)
class GeneratedScenario:
    node_ids: tuple[str, ...]
    messages: tuple[Message, ...]
    encounters: tuple[Encounter, ...]
    seed: int
    name: str
    parameters: tuple[tuple[str, int], ...]

    def simulation(self) -> Simulation:
        return Simulation(
            node_ids=self.node_ids,
            messages=self.messages,
            encounters=self.encounters,
            seed=self.seed,
            scenario=self.name,
            scenario_parameters=self.parameters,
        )


def _generate_messages(
    *,
    node_ids: tuple[str, ...],
    message_count: int,
    latest_creation_time: int,
    payload_size: int,
    ttl_seconds: int,
    max_hops: int,
    id_generator: MessageIdGenerator,
    message_random: random.Random,
) -> tuple[Message, ...]:
    messages: list[Message] = []

    for _ in range(message_count):
        source_index = message_random.randrange(len(node_ids))
        destination_index = message_random.randrange(len(node_ids) - 1)
        if destination_index >= source_index:
            destination_index += 1
        messages.append(
            Message(
                message_id=id_generator.next_id(),
                source=node_ids[source_index],
                destination=node_ids[destination_index],
                created_at=message_random.randrange(latest_creation_time + 1),
                payload_size=payload_size,
                ttl_seconds=ttl_seconds,
                max_hops=max_hops,
            )
        )

    return tuple(messages)


def generate_uniform_contact_scenario(
    config: MeshScenarioConfig, *, seed: int = DEFAULT_SEED
) -> GeneratedScenario:
    """Create a bounded synthetic contact trace without physical movement."""

    id_generator = MessageIdGenerator(seed)
    message_random = random.Random(f"lantern-messages-v1:{seed}")
    encounter_random = random.Random(f"lantern-encounters-v1:{seed}")
    node_ids = tuple(f"node{index:03d}" for index in range(config.node_count))
    messages = _generate_messages(
        node_ids=node_ids,
        message_count=config.message_count,
        latest_creation_time=config.encounter_count // 4,
        payload_size=config.payload_size,
        ttl_seconds=config.ttl_seconds,
        max_hops=config.max_hops,
        id_generator=id_generator,
        message_random=message_random,
    )

    encounters = [
        Encounter(
            at=index + 1,
            left=node_ids[index],
            right=node_ids[(index + 1) % config.node_count],
        )
        for index in range(config.node_count)
    ]
    for index in range(config.node_count, config.encounter_count):
        left_index = encounter_random.randrange(config.node_count)
        right_index = encounter_random.randrange(config.node_count - 1)
        if right_index >= left_index:
            right_index += 1
        encounters.append(
            Encounter(
                at=index + 1,
                left=node_ids[left_index],
                right=node_ids[right_index],
            )
        )

    return GeneratedScenario(
        node_ids=node_ids,
        messages=messages,
        encounters=tuple(encounters),
        seed=seed,
        name="uniform_contacts",
        parameters=config.parameters(),
    )


def generate_contact_round_scenario(
    config: ContactRoundScenarioConfig, *, seed: int = DEFAULT_SEED
) -> GeneratedScenario:
    """Create bounded contact rounds with at most one meeting per node."""

    id_generator = MessageIdGenerator(seed)
    message_random = random.Random(f"lantern-round-messages-v1:{seed}")
    encounter_random = random.Random(f"lantern-round-encounters-v1:{seed}")
    node_ids = tuple(f"node{index:03d}" for index in range(config.node_count))
    messages = _generate_messages(
        node_ids=node_ids,
        message_count=config.message_count,
        latest_creation_time=config.round_count // 4,
        payload_size=config.payload_size,
        ttl_seconds=config.ttl_seconds,
        max_hops=config.max_hops,
        id_generator=id_generator,
        message_random=message_random,
    )

    encounters: list[Encounter] = []
    for round_index in range(config.round_count):
        shuffled_nodes = list(node_ids)
        encounter_random.shuffle(shuffled_nodes)
        for pair_index in range(0, config.node_count - 1, 2):
            encounters.append(
                Encounter(
                    at=round_index + 1,
                    left=shuffled_nodes[pair_index],
                    right=shuffled_nodes[pair_index + 1],
                )
            )

    return GeneratedScenario(
        node_ids=node_ids,
        messages=messages,
        encounters=tuple(encounters),
        seed=seed,
        name="uniform_contact_rounds",
        parameters=config.parameters(),
    )


def generate_configured_scenario(
    config: ScenarioConfig, *, seed: int = DEFAULT_SEED
) -> GeneratedScenario:
    if isinstance(config, MeshScenarioConfig):
        return generate_uniform_contact_scenario(config, seed=seed)
    if isinstance(config, ContactRoundScenarioConfig):
        return generate_contact_round_scenario(config, seed=seed)
    raise SimulationValidationError("unsupported scenario configuration")


def run_uniform_contact_scenario(
    policy: RoutingPolicy,
    *,
    config: MeshScenarioConfig,
    seed: int = DEFAULT_SEED,
    network_conditions: NetworkConditions | None = None,
    storage_quota: StorageQuota | None = None,
    tombstone_config: TombstoneConfig | None = None,
) -> SimulationResult:
    scenario = generate_uniform_contact_scenario(config, seed=seed)
    return scenario.simulation().run(
        policy,
        network_conditions=network_conditions,
        storage_quota=storage_quota,
        tombstone_config=tombstone_config,
    )


def run_configured_scenario(
    policy: RoutingPolicy,
    *,
    config: ScenarioConfig,
    seed: int = DEFAULT_SEED,
    network_conditions: NetworkConditions | None = None,
    storage_quota: StorageQuota | None = None,
    tombstone_config: TombstoneConfig | None = None,
) -> SimulationResult:
    scenario = generate_configured_scenario(config, seed=seed)
    return scenario.simulation().run(
        policy,
        network_conditions=network_conditions,
        storage_quota=storage_quota,
        tombstone_config=tombstone_config,
    )


def run_three_node_chain(
    policy: RoutingPolicy,
    *,
    seed: int = DEFAULT_SEED,
    payload_size: int = 256,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    max_hops: int = DEFAULT_MAX_HOPS,
    network_conditions: NetworkConditions | None = None,
    storage_quota: StorageQuota | None = None,
    tombstone_config: TombstoneConfig | None = None,
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
        scenario="three_node_chain",
        scenario_parameters=(
            ("max_hops", max_hops),
            ("payload_size", payload_size),
            ("ttl_seconds", ttl_seconds),
        ),
    )
    return simulation.run(
        policy,
        network_conditions=network_conditions,
        storage_quota=storage_quota,
        tombstone_config=tombstone_config,
    )
