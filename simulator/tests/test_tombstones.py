# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import pytest

from lantern_sim.model import SimulationValidationError
from lantern_sim.tombstones import TombstoneConfig, TombstoneStore


@pytest.mark.parametrize(
    ("arguments", "field_name"),
    [
        ({"max_entries": 0}, "max_entries"),
        ({"max_entries": 100_001}, "max_entries"),
        ({"retention_seconds": 59}, "retention_seconds"),
        ({"retention_seconds": 604_801}, "retention_seconds"),
        ({"max_entries": True}, "max_entries"),
    ],
)
def test_tombstone_config_rejects_invalid_values(
    arguments: dict[str, object], field_name: str
) -> None:
    with pytest.raises(SimulationValidationError, match=field_name):
        TombstoneConfig(**arguments)  # type: ignore[arg-type]


def test_tombstone_blocks_id_until_expiration_boundary() -> None:
    store = TombstoneStore(TombstoneConfig(max_entries=2, retention_seconds=60))
    message_id = "0" * 32

    store.add(message_id, at=10)

    assert store.contains(message_id, at=69) is True
    assert store.contains(message_id, at=70) is False
    assert store.entry_count == 0


def test_tombstone_store_evicts_oldest_entry_when_full() -> None:
    store = TombstoneStore(TombstoneConfig(max_entries=2, retention_seconds=300))
    oldest_id = "0" * 32
    second_id = "1" * 32
    incoming_id = "2" * 32
    store.add(oldest_id, at=10)
    store.add(second_id, at=20)

    result = store.add(incoming_id, at=30)

    assert tuple(item.message_id for item in result.evicted) == (oldest_id,)
    assert store.contains(oldest_id, at=30) is False
    assert store.contains(second_id, at=30) is True
    assert store.contains(incoming_id, at=30) is True
    assert store.entry_count == 2


def test_readding_same_id_refreshes_without_growing_store() -> None:
    store = TombstoneStore(TombstoneConfig(max_entries=1, retention_seconds=60))
    message_id = "0" * 32
    store.add(message_id, at=10)

    result = store.add(message_id, at=20)

    assert result.evicted == ()
    assert result.entry.expires_at == 80
    assert store.entry_count == 1


def test_purge_expired_returns_entries_in_message_id_order() -> None:
    store = TombstoneStore(TombstoneConfig(max_entries=2, retention_seconds=60))
    store.add("1" * 32, at=0)
    store.add("0" * 32, at=0)

    expired = store.purge_expired(at=60)

    assert [item.message_id for item in expired] == ["0" * 32, "1" * 32]
    assert store.entry_count == 0
