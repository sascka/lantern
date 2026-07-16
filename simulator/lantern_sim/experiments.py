# SPDX-License-Identifier: MPL-2.0

"""Bounded batch experiments for reproducible routing comparisons."""

from __future__ import annotations

from dataclasses import dataclass

from lantern_sim.faults import NetworkConditions
from lantern_sim.model import (
    MAX_SEED,
    SimulationLimitError,
    SimulationValidationError,
    StorageQuota,
)
from lantern_sim.routing import RoutingPolicy
from lantern_sim.scenarios import MeshScenarioConfig, run_uniform_contact_scenario
from lantern_sim.simulation import SimulationResult
from lantern_sim.tombstones import TombstoneConfig

MAX_BATCH_SEEDS = 10
MAX_BATCH_SCENARIOS = 4
MAX_BATCH_RUNS = 60
BATCH_FORMAT_VERSION = 1


@dataclass(frozen=True, slots=True)
class BatchExperimentConfig:
    scenarios: tuple[MeshScenarioConfig, ...]
    seeds: tuple[int, ...]

    def __post_init__(self) -> None:
        if not 1 <= len(self.scenarios) <= MAX_BATCH_SCENARIOS:
            raise SimulationValidationError(
                "batch scenarios must contain between 1 and "
                f"{MAX_BATCH_SCENARIOS} entries"
            )
        if len(set(self.scenarios)) != len(self.scenarios):
            raise SimulationValidationError("batch scenarios must be unique")
        if not 1 <= len(self.seeds) <= MAX_BATCH_SEEDS:
            raise SimulationValidationError(
                f"batch seeds must contain between 1 and {MAX_BATCH_SEEDS} entries"
            )

        seen_seeds: set[int] = set()
        for seed in self.seeds:
            if isinstance(seed, bool) or not isinstance(seed, int):
                raise SimulationValidationError("every batch seed must be an integer")
            if not 0 <= seed <= MAX_SEED:
                raise SimulationValidationError(
                    f"every batch seed must be between 0 and {MAX_SEED}"
                )
            if seed in seen_seeds:
                raise SimulationValidationError("batch seeds must be unique")
            seen_seeds.add(seed)


@dataclass(frozen=True, slots=True)
class CompactRunResult:
    seed: int
    scenario_parameters: tuple[tuple[str, int], ...]
    policy: str
    policy_parameters: tuple[tuple[str, int], ...]
    message_count: int
    delivered_count: int
    total_delivery_delay: int
    attempt_count: int
    bytes_attempted: int
    transmission_count: int
    bytes_transmitted: int
    lost_attempt_count: int
    duplicate_attempt_count: int
    removal_count: int
    eviction_count: int
    blocked_transfer_count: int
    quota_rejection_count: int
    tombstone_rejection_count: int
    tombstone_event_count: int
    peak_stored_messages: int
    peak_stored_bytes: int
    peak_node_stored_messages: int
    peak_node_stored_bytes: int
    peak_node_tombstones: int

    @classmethod
    def from_simulation(cls, result: SimulationResult) -> CompactRunResult:
        return cls(
            seed=result.seed,
            scenario_parameters=result.scenario_parameters,
            policy=result.policy,
            policy_parameters=result.policy_parameters,
            message_count=result.message_count,
            delivered_count=result.delivered_count,
            total_delivery_delay=sum(item.delay for item in result.deliveries),
            attempt_count=result.attempt_count,
            bytes_attempted=result.bytes_attempted,
            transmission_count=result.transmission_count,
            bytes_transmitted=result.bytes_transmitted,
            lost_attempt_count=result.lost_attempt_count,
            duplicate_attempt_count=result.duplicate_attempt_count,
            removal_count=len(result.removals),
            eviction_count=result.eviction_count,
            blocked_transfer_count=len(result.blocked_transfers),
            quota_rejection_count=result.quota_rejection_count,
            tombstone_rejection_count=result.tombstone_rejection_count,
            tombstone_event_count=len(result.tombstone_events),
            peak_stored_messages=result.peak_stored_messages,
            peak_stored_bytes=result.peak_stored_bytes,
            peak_node_stored_messages=result.peak_node_stored_messages,
            peak_node_stored_bytes=result.peak_node_stored_bytes,
            peak_node_tombstones=result.peak_node_tombstones,
        )

    @property
    def delivery_rate(self) -> float:
        return self.delivered_count / self.message_count

    @property
    def average_delivery_delay(self) -> float | None:
        if self.delivered_count == 0:
            return None
        return self.total_delivery_delay / self.delivered_count

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt_count": self.attempt_count,
            "average_delivery_delay": self.average_delivery_delay,
            "blocked_transfer_count": self.blocked_transfer_count,
            "bytes_attempted": self.bytes_attempted,
            "bytes_transmitted": self.bytes_transmitted,
            "delivered_count": self.delivered_count,
            "delivery_rate": self.delivery_rate,
            "duplicate_attempt_count": self.duplicate_attempt_count,
            "eviction_count": self.eviction_count,
            "lost_attempt_count": self.lost_attempt_count,
            "message_count": self.message_count,
            "peak_node_stored_bytes": self.peak_node_stored_bytes,
            "peak_node_stored_messages": self.peak_node_stored_messages,
            "peak_node_tombstones": self.peak_node_tombstones,
            "peak_stored_bytes": self.peak_stored_bytes,
            "peak_stored_messages": self.peak_stored_messages,
            "policy": self.policy,
            "policy_parameters": dict(self.policy_parameters),
            "quota_rejection_count": self.quota_rejection_count,
            "removal_count": self.removal_count,
            "scenario_parameters": dict(self.scenario_parameters),
            "seed": self.seed,
            "tombstone_event_count": self.tombstone_event_count,
            "tombstone_rejection_count": self.tombstone_rejection_count,
            "total_delivery_delay": self.total_delivery_delay,
            "transmission_count": self.transmission_count,
        }


@dataclass(frozen=True, slots=True)
class AggregateResult:
    scenario_parameters: tuple[tuple[str, int], ...]
    policy: str
    policy_parameters: tuple[tuple[str, int], ...]
    run_count: int
    total_messages: int
    total_delivered: int
    total_delivery_delay: int
    total_attempts: int
    total_bytes_attempted: int
    total_transmissions: int
    total_bytes_transmitted: int
    total_lost_attempts: int
    total_duplicate_attempts: int
    total_removals: int
    total_evictions: int
    total_blocked_transfers: int
    total_quota_rejections: int
    total_tombstone_rejections: int
    total_tombstone_events: int
    max_peak_stored_messages: int
    max_peak_stored_bytes: int
    max_peak_node_stored_messages: int
    max_peak_node_stored_bytes: int
    max_peak_node_tombstones: int

    @classmethod
    def from_runs(
        cls, runs: tuple[CompactRunResult, ...]
    ) -> AggregateResult:
        if not runs:
            raise SimulationValidationError("cannot aggregate an empty run list")
        first = runs[0]
        if any(
            item.scenario_parameters != first.scenario_parameters
            or item.policy != first.policy
            or item.policy_parameters != first.policy_parameters
            for item in runs
        ):
            raise SimulationValidationError(
                "aggregate runs must use one scenario and one policy"
            )

        return cls(
            scenario_parameters=first.scenario_parameters,
            policy=first.policy,
            policy_parameters=first.policy_parameters,
            run_count=len(runs),
            total_messages=sum(item.message_count for item in runs),
            total_delivered=sum(item.delivered_count for item in runs),
            total_delivery_delay=sum(item.total_delivery_delay for item in runs),
            total_attempts=sum(item.attempt_count for item in runs),
            total_bytes_attempted=sum(item.bytes_attempted for item in runs),
            total_transmissions=sum(item.transmission_count for item in runs),
            total_bytes_transmitted=sum(
                item.bytes_transmitted for item in runs
            ),
            total_lost_attempts=sum(item.lost_attempt_count for item in runs),
            total_duplicate_attempts=sum(
                item.duplicate_attempt_count for item in runs
            ),
            total_removals=sum(item.removal_count for item in runs),
            total_evictions=sum(item.eviction_count for item in runs),
            total_blocked_transfers=sum(
                item.blocked_transfer_count for item in runs
            ),
            total_quota_rejections=sum(
                item.quota_rejection_count for item in runs
            ),
            total_tombstone_rejections=sum(
                item.tombstone_rejection_count for item in runs
            ),
            total_tombstone_events=sum(
                item.tombstone_event_count for item in runs
            ),
            max_peak_stored_messages=max(
                item.peak_stored_messages for item in runs
            ),
            max_peak_stored_bytes=max(item.peak_stored_bytes for item in runs),
            max_peak_node_stored_messages=max(
                item.peak_node_stored_messages for item in runs
            ),
            max_peak_node_stored_bytes=max(
                item.peak_node_stored_bytes for item in runs
            ),
            max_peak_node_tombstones=max(
                item.peak_node_tombstones for item in runs
            ),
        )

    @property
    def delivery_rate(self) -> float:
        return self.total_delivered / self.total_messages

    @property
    def average_delivery_delay(self) -> float | None:
        if self.total_delivered == 0:
            return None
        return self.total_delivery_delay / self.total_delivered

    def to_dict(self) -> dict[str, object]:
        return {
            "average_delivery_delay": self.average_delivery_delay,
            "delivery_rate": self.delivery_rate,
            "max_peak_node_stored_bytes": self.max_peak_node_stored_bytes,
            "max_peak_node_stored_messages": (
                self.max_peak_node_stored_messages
            ),
            "max_peak_node_tombstones": self.max_peak_node_tombstones,
            "max_peak_stored_bytes": self.max_peak_stored_bytes,
            "max_peak_stored_messages": self.max_peak_stored_messages,
            "policy": self.policy,
            "policy_parameters": dict(self.policy_parameters),
            "run_count": self.run_count,
            "scenario_parameters": dict(self.scenario_parameters),
            "total_attempts": self.total_attempts,
            "total_blocked_transfers": self.total_blocked_transfers,
            "total_bytes_attempted": self.total_bytes_attempted,
            "total_bytes_transmitted": self.total_bytes_transmitted,
            "total_delivered": self.total_delivered,
            "total_delivery_delay": self.total_delivery_delay,
            "total_duplicate_attempts": self.total_duplicate_attempts,
            "total_evictions": self.total_evictions,
            "total_lost_attempts": self.total_lost_attempts,
            "total_messages": self.total_messages,
            "total_quota_rejections": self.total_quota_rejections,
            "total_removals": self.total_removals,
            "total_tombstone_events": self.total_tombstone_events,
            "total_tombstone_rejections": self.total_tombstone_rejections,
            "total_transmissions": self.total_transmissions,
        }


@dataclass(frozen=True, slots=True)
class BatchExperimentResult:
    config: BatchExperimentConfig
    network_conditions: NetworkConditions
    storage_quota: StorageQuota
    tombstone_config: TombstoneConfig
    runs: tuple[CompactRunResult, ...]
    aggregates: tuple[AggregateResult, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "aggregates": [item.to_dict() for item in self.aggregates],
            "format_version": BATCH_FORMAT_VERSION,
            "network_conditions": self.network_conditions.to_dict(),
            "run_count": len(self.runs),
            "runs": [item.to_dict() for item in self.runs],
            "scenario": "uniform_contacts_batch",
            "scenarios": [
                dict(item.parameters()) for item in self.config.scenarios
            ],
            "seeds": list(self.config.seeds),
            "spdx_license": "MPL-2.0",
            "storage_quota": self.storage_quota.to_dict(),
            "tombstone_config": self.tombstone_config.to_dict(),
        }


def run_batch_experiment(
    config: BatchExperimentConfig,
    policies: tuple[RoutingPolicy, ...],
    *,
    network_conditions: NetworkConditions | None = None,
    storage_quota: StorageQuota | None = None,
    tombstone_config: TombstoneConfig | None = None,
) -> BatchExperimentResult:
    if not policies:
        raise SimulationValidationError("batch policies must not be empty")
    policy_keys = tuple((item.name, item.parameters) for item in policies)
    if len(set(policy_keys)) != len(policy_keys):
        raise SimulationValidationError("batch policies must be unique")

    run_count = len(config.scenarios) * len(config.seeds) * len(policies)
    if run_count > MAX_BATCH_RUNS:
        raise SimulationLimitError(
            f"batch run count must not exceed {MAX_BATCH_RUNS}"
        )

    conditions = network_conditions or NetworkConditions()
    quota = storage_quota or StorageQuota()
    tombstones = tombstone_config or TombstoneConfig()
    runs: list[CompactRunResult] = []

    for scenario in config.scenarios:
        for seed in config.seeds:
            for policy in policies:
                result = run_uniform_contact_scenario(
                    policy,
                    config=scenario,
                    seed=seed,
                    network_conditions=conditions,
                    storage_quota=quota,
                    tombstone_config=tombstones,
                )
                runs.append(CompactRunResult.from_simulation(result))

    compact_runs = tuple(runs)
    aggregates: list[AggregateResult] = []
    for scenario in config.scenarios:
        parameters = scenario.parameters()
        for policy in policies:
            matching_runs = tuple(
                item
                for item in compact_runs
                if item.scenario_parameters == parameters
                and item.policy == policy.name
                and item.policy_parameters == policy.parameters
            )
            aggregates.append(AggregateResult.from_runs(matching_runs))

    return BatchExperimentResult(
        config=config,
        network_conditions=conditions,
        storage_quota=quota,
        tombstone_config=tombstones,
        runs=compact_runs,
        aggregates=tuple(aggregates),
    )
