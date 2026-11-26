from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cairn.core.tristate import Tri
from cairn.provenance.avb import AvbChainPartition, load_vbmeta
from cairn.rollback.oracle import (
    MAX_ROLLBACK_INDEX,
    CounterKind,
    OtaDowngradeSignal,
    RollbackCounter,
    RollbackError,
    avb_rollback_inputs,
    evaluate_avb_rollback,
    evaluate_rollback,
)

FIXTURES = Path(__file__).parent / "fixtures" / "avb"
CHAIN_TOP = FIXTURES / "chain" / "vbmeta.img"
CHAIN_BOOT = FIXTURES / "chain" / "boot.img"


def _counter(
    name: str = "avb:main",
    *,
    package_value: int = 5,
    stored_value: int | None = None,
    stored_source: str = "unknown",
    location: int | None = 0,
    slot: str | None = None,
    kind: CounterKind = CounterKind.AVB,
    catalog_minimum: int | None = None,
    catalog_maximum: int | None = None,
) -> RollbackCounter:
    return RollbackCounter(
        name=name,
        kind=kind,
        package_value=package_value,
        stored_value=stored_value,
        location=location,
        slot=slot,
        source="test",
        stored_source=stored_source,
        catalog_minimum=catalog_minimum,
        catalog_maximum=catalog_maximum,
    )


def test_known_safe_package_is_true() -> None:
    report = evaluate_rollback([_counter(package_value=7, stored_value=7, stored_source="device")])

    assert report.state is Tri.TRUE
    assert report.blocks is False
    assert "at least the stored index 7" in report.reasons[0]


def test_package_above_the_stored_index_is_true() -> None:
    report = evaluate_rollback([_counter(package_value=9, stored_value=7, stored_source="device")])

    assert report.state is Tri.TRUE


def test_definitely_lowering_package_is_false() -> None:
    report = evaluate_rollback([_counter(package_value=6, stored_value=7, stored_source="device")])

    assert report.state is Tri.FALSE
    assert report.blocks is True
    assert "below the stored index 7" in report.reasons[0]


def test_unknown_stored_index_is_unknown() -> None:
    report = evaluate_rollback([_counter(package_value=7)])

    assert report.state is Tri.UNKNOWN
    assert report.blocks is True
    assert "the stored index is unknown" in report.reasons[0]


def test_empty_evaluation_is_unknown_not_true() -> None:
    report = evaluate_rollback([])

    assert report.state is Tri.UNKNOWN
    assert report.reasons == ("no rollback counters were evaluated",)


def test_false_dominates_unknown() -> None:
    report = evaluate_rollback(
        [
            _counter(name="avb:a", package_value=1, stored_value=5, stored_source="device"),
            _counter(name="avb:b", package_value=1),
        ]
    )

    assert report.state is Tri.FALSE


def test_unknown_dominates_true() -> None:
    report = evaluate_rollback(
        [
            _counter(name="avb:a", package_value=9, stored_value=5, stored_source="device"),
            _counter(name="avb:b", package_value=1),
        ]
    )

    assert report.state is Tri.UNKNOWN


def test_catalog_upper_bound_proves_the_package_is_safe() -> None:
    report = evaluate_rollback([_counter(package_value=7, catalog_maximum=7)])

    assert report.state is Tri.TRUE
    assert "at most 7" in report.reasons[0]


def test_catalog_lower_bound_proves_the_package_lowers() -> None:
    report = evaluate_rollback([_counter(package_value=7, catalog_minimum=9)])

    assert report.state is Tri.FALSE
    assert "at least 9" in report.reasons[0]


def test_catalog_bounds_inside_the_range_stay_unknown() -> None:
    report = evaluate_rollback([_counter(package_value=7, catalog_minimum=5, catalog_maximum=9)])

    assert report.state is Tri.UNKNOWN


def test_device_value_wins_over_catalog_and_contradiction_is_reported() -> None:
    report = evaluate_rollback(
        [
            _counter(
                package_value=7,
                stored_value=3,
                stored_source="device",
                catalog_minimum=5,
            )
        ]
    )

    assert report.state is Tri.TRUE
    assert report.warnings
    assert "below the catalog minimum 5" in report.warnings[0]


def test_oem_counter_with_unknown_stored_value_is_unknown() -> None:
    report = evaluate_rollback(
        [_counter(name="oem:samsung_binary_version", kind=CounterKind.OEM, package_value=12)]
    )

    assert report.state is Tri.UNKNOWN
    assert report.findings[0].kind is CounterKind.OEM


def test_ota_signal_keeps_the_verdict_unknown() -> None:
    report = evaluate_rollback(
        [_counter(package_value=7, stored_value=7, stored_source="device")],
        ota=OtaDowngradeSignal(detail="pre-device property present"),
    )

    assert report.state is Tri.UNKNOWN
    assert any("OTA downgrade metadata" in reason for reason in report.reasons)


def test_unresolved_counter_is_unknown() -> None:
    report = evaluate_rollback([], unresolved=("avb:boot",))

    assert report.state is Tri.UNKNOWN
    assert report.findings[0].counter == "avb:boot"
    assert "could not be read" in report.reasons[0]


def test_avb_inputs_from_the_chain_fixture() -> None:
    inputs = avb_rollback_inputs(
        load_vbmeta(CHAIN_TOP),
        {"boot": load_vbmeta(CHAIN_BOOT)},
    )

    assert inputs.unresolved == ()
    names = [counter.name for counter in inputs.counters]
    assert names == ["avb:main", "avb:boot"]
    assert inputs.counters[0].package_value == 1
    assert inputs.counters[0].location == 0
    assert inputs.counters[1].package_value == 3
    assert inputs.counters[1].location == 3


def test_avb_inputs_report_a_missing_chain_image_as_unresolved() -> None:
    inputs = avb_rollback_inputs(load_vbmeta(CHAIN_TOP), {})

    assert inputs.unresolved == ("avb:boot",)
    assert [counter.name for counter in inputs.counters] == ["avb:main"]


def test_avb_evaluation_is_true_when_stored_values_are_known() -> None:
    report = evaluate_avb_rollback(
        load_vbmeta(CHAIN_TOP),
        {"boot": load_vbmeta(CHAIN_BOOT)},
        stored={0: 1, 3: 3},
    )

    assert report.state is Tri.TRUE
    assert len(report.findings) == 2


def test_avb_evaluation_is_false_when_a_chained_counter_is_lowered() -> None:
    report = evaluate_avb_rollback(
        load_vbmeta(CHAIN_TOP),
        {"boot": load_vbmeta(CHAIN_BOOT)},
        stored={0: 1, 3: 4},
    )

    assert report.state is Tri.FALSE
    assert report.findings[1].counter == "avb:boot"
    assert report.findings[1].location == 3


def test_avb_evaluation_is_unknown_without_stored_values() -> None:
    report = evaluate_avb_rollback(
        load_vbmeta(CHAIN_TOP),
        {"boot": load_vbmeta(CHAIN_BOOT)},
    )

    assert report.state is Tri.UNKNOWN
    assert report.findings[0].stored_value is None


def test_avb_evaluation_with_a_missing_chain_is_unknown() -> None:
    report = evaluate_avb_rollback(load_vbmeta(CHAIN_TOP), {})

    assert report.state is Tri.UNKNOWN
    assert any("could not be read" in reason for reason in report.reasons)


def test_per_slot_stored_values_change_the_verdict() -> None:
    image = load_vbmeta(CHAIN_TOP)
    chain = {"boot": load_vbmeta(CHAIN_BOOT)}

    slot_a = evaluate_avb_rollback(image, chain, slot="a", stored={0: 1, 3: 3})
    slot_b = evaluate_avb_rollback(image, chain, slot="b", stored={0: 1, 3: 9})

    assert slot_a.state is Tri.TRUE
    assert slot_b.state is Tri.FALSE
    assert slot_b.findings[1].slot == "b"


def test_report_is_json_serializable() -> None:
    report = evaluate_avb_rollback(
        load_vbmeta(CHAIN_TOP),
        {"boot": load_vbmeta(CHAIN_BOOT)},
        stored={0: 1, 3: 4},
    )

    encoded = json.dumps(report.to_dict(), sort_keys=True)
    assert '"state": "FALSE"' in encoded
    assert '"counter": "avb:boot"' in encoded


def test_counter_validation_rejects_bad_input() -> None:
    with pytest.raises(RollbackError, match="name must not be empty"):
        _counter(name=" ")
    with pytest.raises(RollbackError, match="negative package value"):
        _counter(package_value=-1)
    with pytest.raises(RollbackError, match="negative stored value"):
        _counter(stored_value=-1)
    with pytest.raises(RollbackError, match="stored value without a stored source"):
        _counter(stored_value=3, stored_source="unknown")
    with pytest.raises(RollbackError, match="catalog minimum above its maximum"):
        _counter(catalog_minimum=9, catalog_maximum=3)
    with pytest.raises(RollbackError, match="negative location"):
        _counter(location=-1)


@settings(max_examples=200, deadline=None)
@given(
    package=st.integers(min_value=0, max_value=2**32),
    stored=st.integers(min_value=0, max_value=2**32),
)
def test_verdict_follows_the_documented_inequality(package: int, stored: int) -> None:
    report = evaluate_rollback(
        [_counter(package_value=package, stored_value=stored, stored_source="device")]
    )

    if package < stored:
        assert report.state is Tri.FALSE
    else:
        assert report.state is Tri.TRUE


@settings(max_examples=200, deadline=None)
@given(package=st.integers(min_value=0, max_value=2**32))
def test_unknown_stored_value_never_yields_true(package: int) -> None:
    report = evaluate_rollback([_counter(package_value=package)])

    assert report.state is Tri.UNKNOWN
    assert report.blocks is True


def _nested_boot():
    boot = load_vbmeta(CHAIN_BOOT)
    descriptor = AvbChainPartition(
        rollback_index_location=4,
        partition_name="system",
        public_key=b"nested-key",
        flags=0,
    )
    return replace(boot, descriptors=(descriptor,))


def _nested_system():
    boot = load_vbmeta(CHAIN_BOOT)
    header = replace(boot.header, rollback_index=7, rollback_index_location=0)
    return replace(boot, header=header, descriptors=())


def test_nested_chain_counters_are_followed() -> None:
    inputs = avb_rollback_inputs(
        load_vbmeta(CHAIN_TOP),
        {"boot": _nested_boot(), "system": _nested_system()},
    )

    assert inputs.unresolved == ()
    assert [counter.name for counter in inputs.counters] == [
        "avb:main",
        "avb:boot",
        "avb:system",
    ]
    assert inputs.counters[2].package_value == 7
    assert inputs.counters[2].location == 4


def test_nested_chain_depth_limit_is_unresolved() -> None:
    inputs = avb_rollback_inputs(
        load_vbmeta(CHAIN_TOP),
        {"boot": _nested_boot(), "system": _nested_system()},
        max_depth=1,
    )

    assert [counter.name for counter in inputs.counters] == ["avb:main", "avb:boot"]
    assert inputs.unresolved == ("avb:system",)


def test_chain_cycle_is_unresolved() -> None:
    boot = load_vbmeta(CHAIN_BOOT)
    cycle = AvbChainPartition(
        rollback_index_location=5,
        partition_name="boot",
        public_key=b"cycle-key",
        flags=0,
    )
    inputs = avb_rollback_inputs(
        load_vbmeta(CHAIN_TOP),
        {"boot": replace(boot, descriptors=(cycle,))},
    )

    assert inputs.unresolved == ("avb:boot",)


def test_zero_chain_location_is_unresolved() -> None:
    boot = load_vbmeta(CHAIN_BOOT)
    invalid = AvbChainPartition(
        rollback_index_location=0,
        partition_name="system",
        public_key=b"invalid-key",
        flags=0,
    )
    inputs = avb_rollback_inputs(
        load_vbmeta(CHAIN_TOP),
        {"boot": replace(boot, descriptors=(invalid,))},
    )

    assert inputs.unresolved == ("avb:system",)


def test_counter_rejects_out_of_range_and_inconsistent_values() -> None:
    with pytest.raises(RollbackError, match="64-bit rollback index limit"):
        _counter(package_value=MAX_ROLLBACK_INDEX + 1)
    with pytest.raises(RollbackError, match="64-bit rollback index limit"):
        _counter(stored_value=MAX_ROLLBACK_INDEX + 1, stored_source="device")
    with pytest.raises(RollbackError, match="stored source without a stored value"):
        _counter(stored_value=None, stored_source="device")
    with pytest.raises(RollbackError, match="negative catalog minimum"):
        _counter(catalog_minimum=-1)
    with pytest.raises(RollbackError, match="catalog maximum exceeds"):
        _counter(catalog_maximum=MAX_ROLLBACK_INDEX + 1)
    with pytest.raises(RollbackError, match="stored source must not be empty"):
        _counter(stored_value=3, stored_source=" ")


def test_avb_rollback_inputs_rejects_zero_depth() -> None:
    with pytest.raises(RollbackError, match="max_depth"):
        avb_rollback_inputs(load_vbmeta(CHAIN_TOP), {}, max_depth=0)
