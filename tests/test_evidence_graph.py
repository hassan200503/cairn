from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from cairn.core.errors import EvidenceError
from cairn.core.evidence import Evidence, EvidenceSource
from cairn.core.evidence_graph import EvidenceGraph
from cairn.core.tristate import Tri

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)

STATES = st.sampled_from(list(Tri))
SOURCES = st.sampled_from(list(EvidenceSource))
TIMESTAMPS = st.datetimes(
    min_value=datetime(2000, 1, 1),
    max_value=datetime(2100, 1, 1),
    timezones=st.just(UTC),
)
VALUES = st.one_of(
    st.none(),
    st.text(),
    st.integers(),
    st.booleans(),
    st.floats(allow_nan=False, allow_infinity=False),
)


def test_source_strength_is_ordered_from_weakest_to_strongest() -> None:
    ordered = [
        EvidenceSource.INFERRED,
        EvidenceSource.USER,
        EvidenceSource.CATALOG,
        EvidenceSource.PACKAGE,
        EvidenceSource.PROBED,
    ]
    assert ordered == sorted(EvidenceSource)
    assert max(EvidenceSource) is EvidenceSource.PROBED
    assert [source.is_probe for source in EvidenceSource] == [
        False,
        False,
        False,
        False,
        True,
    ]


def test_evidence_id_is_stable_and_sensitive() -> None:
    fact: Evidence[int] = Evidence.probed(Tri.TRUE, NOW, value=42, max_age=timedelta(minutes=5))
    assert fact.evidence_id == fact.evidence_id
    same = Evidence.probed(Tri.TRUE, NOW, value=42, max_age=timedelta(minutes=5))
    assert same.evidence_id == fact.evidence_id

    different_state = Evidence.probed(Tri.FALSE, NOW, value=42, max_age=timedelta(minutes=5))
    different_time = Evidence.probed(
        Tri.TRUE, NOW + timedelta(seconds=1), value=42, max_age=timedelta(minutes=5)
    )
    different_detail = Evidence.probed(
        Tri.TRUE, NOW, value=42, max_age=timedelta(minutes=5), detail="other"
    )
    assert different_state.evidence_id != fact.evidence_id
    assert different_time.evidence_id != fact.evidence_id
    assert different_detail.evidence_id != fact.evidence_id


@given(state=STATES, source=SOURCES, observed_at=TIMESTAMPS, value=VALUES)
def test_evidence_serialization_roundtrip(
    state: Tri,
    source: EvidenceSource,
    observed_at: datetime,
    value: object,
) -> None:
    fact: Evidence[object] = Evidence(
        state=state,
        source=source,
        observed_at=observed_at,
        value=value,
        max_age=timedelta(seconds=30),
        detail="detail",
        boot_id="boot-7",
    )
    loaded = Evidence.from_dict(fact.to_dict())
    assert loaded == fact
    assert loaded.evidence_id == fact.evidence_id


def test_serialized_id_detects_tampering() -> None:
    fact = Evidence.probed(Tri.TRUE, NOW, value="yes")
    raw = fact.to_dict()
    raw["state"] = "FALSE"
    with pytest.raises(EvidenceError, match="mismatch"):
        Evidence.from_dict(raw)


def test_from_dict_rejects_bad_input() -> None:
    with pytest.raises(EvidenceError, match="JSON object"):
        Evidence.from_dict([])
    with pytest.raises(EvidenceError, match="state"):
        Evidence.from_dict({"state": "MAYBE", "source": "PROBED", "observed_at": NOW.isoformat()})
    with pytest.raises(EvidenceError, match="source"):
        Evidence.from_dict({"state": "TRUE", "source": "ORACLE", "observed_at": NOW.isoformat()})
    with pytest.raises(EvidenceError, match="timezone"):
        Evidence.from_dict(
            {"state": "TRUE", "source": "PROBED", "observed_at": "2026-11-25T12:00:00"}
        )
    with pytest.raises(EvidenceError, match="max_age_s"):
        Evidence.from_dict(
            {
                "state": "TRUE",
                "source": "PROBED",
                "observed_at": NOW.isoformat(),
                "max_age_s": 0,
            }
        )
    with pytest.raises(EvidenceError, match="JSON-serializable"):
        Evidence.from_dict(
            {
                "state": "TRUE",
                "source": "PROBED",
                "observed_at": NOW.isoformat(),
                "value": object(),
            }
        )


def test_graph_stamps_the_current_epoch() -> None:
    graph = EvidenceGraph(boot_id="boot-1")
    stored = graph.record("unlocked", Evidence.probed(Tri.TRUE, NOW))
    assert stored.boot_id == "boot-1"
    assert graph.get("unlocked") is stored
    assert graph.is_usable("unlocked", NOW)


def test_graph_rejects_evidence_from_another_epoch() -> None:
    graph = EvidenceGraph(boot_id="boot-1")
    old = Evidence.probed(Tri.TRUE, NOW, boot_id="boot-0")
    with pytest.raises(EvidenceError, match="belongs to boot"):
        graph.record("unlocked", old)


def test_reboot_invalidates_earlier_probes() -> None:
    graph = EvidenceGraph(boot_id="boot-0")
    graph.record("unlocked", Evidence.probed(Tri.TRUE, NOW))
    assert graph.is_usable("unlocked", NOW)

    graph.reboot("boot-1")
    assert graph.get("unlocked") is not None
    assert not graph.is_usable("unlocked", NOW)
    with pytest.raises(EvidenceError, match="from boot"):
        graph.require_usable("unlocked", NOW)

    graph.record("unlocked", Evidence.probed(Tri.TRUE, NOW))
    assert graph.is_usable("unlocked", NOW)


def test_reboot_requires_a_new_epoch() -> None:
    graph = EvidenceGraph(boot_id="boot-0")
    with pytest.raises(EvidenceError, match="already"):
        graph.reboot("boot-0")
    with pytest.raises(ValueError, match="not be empty"):
        graph.reboot("")


def test_graph_refuses_inferred_and_stale_evidence() -> None:
    graph = EvidenceGraph()
    graph.record("inferred", Evidence.unknown(NOW, source=EvidenceSource.INFERRED))
    assert not graph.is_usable("inferred", NOW)
    with pytest.raises(EvidenceError, match="inferred"):
        graph.require_usable("inferred", NOW)

    graph.record(
        "stale",
        Evidence.probed(
            Tri.TRUE,
            NOW - timedelta(minutes=5),
            max_age=timedelta(minutes=1),
        ),
    )
    assert not graph.is_usable("stale", NOW)
    with pytest.raises(EvidenceError, match="stale"):
        graph.require_usable("stale", NOW)


@given(
    age_s=st.integers(min_value=0, max_value=1_000_000),
    max_age_s=st.integers(min_value=1, max_value=1_000_000),
)
def test_freshness_at_use(age_s: int, max_age_s: int) -> None:
    graph = EvidenceGraph()
    observed_at = NOW - timedelta(seconds=age_s)
    graph.record(
        "fact",
        Evidence.probed(Tri.TRUE, observed_at, max_age=timedelta(seconds=max_age_s)),
    )
    assert graph.is_usable("fact", NOW) == (age_s <= max_age_s)


def test_graph_roundtrip_preserves_epochs_and_keys() -> None:
    graph = EvidenceGraph(boot_id="boot-0")
    graph.record("old", Evidence.probed(Tri.TRUE, NOW, value="old"))
    graph.reboot("boot-1")
    graph.record("new", Evidence.probed(Tri.TRUE, NOW, value="new"))

    loaded = EvidenceGraph.loads(graph.dumps())
    assert loaded.boot_id == "boot-1"
    assert loaded.keys() == ("old", "new")
    assert not loaded.is_usable("old", NOW)
    assert loaded.is_usable("new", NOW)
    assert loaded.to_dict() == graph.to_dict()


def test_graph_from_dict_rejects_bad_input() -> None:
    with pytest.raises(EvidenceError, match="JSON object"):
        EvidenceGraph.from_dict([])
    with pytest.raises(EvidenceError, match="schema_version"):
        EvidenceGraph.from_dict({"schema_version": 99, "boot_id": "boot-0", "facts": {}})
    with pytest.raises(EvidenceError, match="boot_id"):
        EvidenceGraph.from_dict({"schema_version": 1, "boot_id": "", "facts": {}})
    with pytest.raises(EvidenceError, match="facts"):
        EvidenceGraph.from_dict({"schema_version": 1, "boot_id": "boot-0", "facts": []})
    with pytest.raises(EvidenceError, match="valid JSON"):
        EvidenceGraph.loads("{not json")
