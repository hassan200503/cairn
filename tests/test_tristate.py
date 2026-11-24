from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cairn.core.evidence import Evidence, EvidenceSource
from cairn.core.tristate import Tri

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)


def test_tri_ordering_is_safety_ordering() -> None:
    assert Tri.FALSE < Tri.UNKNOWN < Tri.TRUE


def test_tri_is_not_truthy() -> None:
    with pytest.raises(TypeError, match="not truthy"):
        bool(Tri.TRUE)


def test_kleene_and() -> None:
    assert Tri.TRUE.and_(Tri.TRUE) is Tri.TRUE
    assert Tri.TRUE.and_(Tri.UNKNOWN) is Tri.UNKNOWN
    assert Tri.TRUE.and_(Tri.FALSE) is Tri.FALSE
    assert Tri.UNKNOWN.and_(Tri.FALSE) is Tri.FALSE
    assert Tri.UNKNOWN.and_(Tri.UNKNOWN) is Tri.UNKNOWN


def test_kleene_or() -> None:
    assert Tri.FALSE.or_(Tri.FALSE) is Tri.FALSE
    assert Tri.FALSE.or_(Tri.UNKNOWN) is Tri.UNKNOWN
    assert Tri.FALSE.or_(Tri.TRUE) is Tri.TRUE
    assert Tri.UNKNOWN.or_(Tri.TRUE) is Tri.TRUE
    assert Tri.UNKNOWN.or_(Tri.UNKNOWN) is Tri.UNKNOWN


def test_negation() -> None:
    assert Tri.TRUE.negate() is Tri.FALSE
    assert Tri.FALSE.negate() is Tri.TRUE
    assert Tri.UNKNOWN.negate() is Tri.UNKNOWN


def test_blocks_policy() -> None:
    assert Tri.TRUE.blocks is False
    assert Tri.FALSE.blocks is True
    assert Tri.UNKNOWN.blocks is True


def test_reducers() -> None:
    assert Tri.all_of([]) is Tri.TRUE
    assert Tri.any_of([]) is Tri.FALSE
    assert Tri.all_of([Tri.TRUE, Tri.UNKNOWN, Tri.TRUE]) is Tri.UNKNOWN
    assert Tri.any_of([Tri.FALSE, Tri.UNKNOWN, Tri.FALSE]) is Tri.UNKNOWN
    assert Tri.all_of([Tri.TRUE, Tri.FALSE, Tri.UNKNOWN]) is Tri.FALSE


def test_evidence_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        Evidence(state=Tri.TRUE, source=EvidenceSource.PROBED, observed_at=datetime(2026, 11, 24))


def test_evidence_freshness() -> None:
    fact: Evidence[int] = Evidence.probed(
        Tri.TRUE,
        NOW - timedelta(minutes=5),
        value=42,
        max_age=timedelta(minutes=10),
    )
    assert fact.is_fresh(NOW) is True
    assert fact.is_usable(NOW) is True

    stale = Evidence.probed(
        Tri.TRUE,
        NOW - timedelta(minutes=11),
        value=42,
        max_age=timedelta(minutes=10),
    )
    assert stale.is_fresh(NOW) is False
    assert stale.is_usable(NOW) is False


def test_inferred_evidence_is_not_usable_even_when_fresh() -> None:
    fact: Evidence[str] = Evidence.unknown(NOW, source=EvidenceSource.INFERRED)
    assert fact.is_usable(NOW) is False


def test_max_age_must_be_positive() -> None:
    with pytest.raises(ValueError, match="max_age"):
        Evidence.probed(Tri.TRUE, NOW, max_age=timedelta(0))
