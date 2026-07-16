# SPDX-License-Identifier: MPL-2.0

"""Deterministic channel faults for reproducible routing experiments."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import TypeVar

from lantern_sim.model import SimulationValidationError

MIN_PERCENT = 0
MAX_PERCENT = 100

_T = TypeVar("_T")


def _validate_percent(value: int, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SimulationValidationError(f"{field_name} must be an integer")
    if not MIN_PERCENT <= value <= MAX_PERCENT:
        raise SimulationValidationError(
            f"{field_name} must be between {MIN_PERCENT} and {MAX_PERCENT}"
        )


@dataclass(frozen=True, slots=True)
class NetworkConditions:
    """Loss, duplication and batch reordering applied to transfer attempts."""

    loss_percent: int = 0
    duplicate_percent: int = 0
    reorder: bool = False

    def __post_init__(self) -> None:
        _validate_percent(self.loss_percent, "loss_percent")
        _validate_percent(self.duplicate_percent, "duplicate_percent")
        if not isinstance(self.reorder, bool):
            raise SimulationValidationError("reorder must be a boolean")

    def is_lost(
        self,
        *,
        seed: int,
        encounter_index: int,
        sender: str,
        receiver: str,
        message_id: str,
    ) -> bool:
        return self._sample(
            percent=self.loss_percent,
            purpose="loss",
            seed=seed,
            encounter_index=encounter_index,
            sender=sender,
            receiver=receiver,
            message_id=message_id,
        )

    def is_duplicated(
        self,
        *,
        seed: int,
        encounter_index: int,
        sender: str,
        receiver: str,
        message_id: str,
    ) -> bool:
        return self._sample(
            percent=self.duplicate_percent,
            purpose="duplicate",
            seed=seed,
            encounter_index=encounter_index,
            sender=sender,
            receiver=receiver,
            message_id=message_id,
        )

    def order_batch(self, items: tuple[_T, ...]) -> tuple[_T, ...]:
        if not self.reorder:
            return items
        return tuple(reversed(items))

    def to_dict(self) -> dict[str, int | bool]:
        return {
            "duplicate_percent": self.duplicate_percent,
            "loss_percent": self.loss_percent,
            "reorder": self.reorder,
        }

    @staticmethod
    def _sample(
        *,
        percent: int,
        purpose: str,
        seed: int,
        encounter_index: int,
        sender: str,
        receiver: str,
        message_id: str,
    ) -> bool:
        if percent == MIN_PERCENT:
            return False
        if percent == MAX_PERCENT:
            return True

        stable_seed = (
            f"lantern-sim-v1:{purpose}:{seed}:{encounter_index}:"
            f"{sender}:{receiver}:{message_id}"
        )
        return random.Random(stable_seed).randrange(MAX_PERCENT) < percent
