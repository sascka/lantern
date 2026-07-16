# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import pytest

from lantern_sim.faults import NetworkConditions
from lantern_sim.model import SimulationValidationError


@pytest.mark.parametrize("percent", [0, 100])
def test_network_conditions_accept_percent_boundaries(percent: int) -> None:
    conditions = NetworkConditions(loss_percent=percent, duplicate_percent=percent)

    assert conditions.loss_percent == percent
    assert conditions.duplicate_percent == percent


@pytest.mark.parametrize("field_name", ["loss_percent", "duplicate_percent"])
@pytest.mark.parametrize("value", [-1, 101, True])
def test_network_conditions_reject_invalid_percent(
    field_name: str, value: object
) -> None:
    arguments = {field_name: value}

    with pytest.raises(SimulationValidationError, match=field_name):
        NetworkConditions(**arguments)  # type: ignore[arg-type]


def test_network_conditions_reject_non_boolean_reorder() -> None:
    with pytest.raises(SimulationValidationError, match="reorder"):
        NetworkConditions(reorder=1)  # type: ignore[arg-type]


def test_fault_sampling_is_stable_for_the_same_transfer() -> None:
    conditions = NetworkConditions(loss_percent=50, duplicate_percent=50)
    arguments = {
        "seed": 42,
        "encounter_index": 3,
        "sender": "alice",
        "receiver": "relay",
        "message_id": "0" * 32,
    }

    assert conditions.is_lost(**arguments) == conditions.is_lost(**arguments)
    assert conditions.is_duplicated(**arguments) == conditions.is_duplicated(
        **arguments
    )


def test_reorder_reverses_only_the_selected_batch() -> None:
    conditions = NetworkConditions(reorder=True)

    assert conditions.order_batch(("first", "second", "third")) == (
        "third",
        "second",
        "first",
    )
