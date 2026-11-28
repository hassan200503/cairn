"""Rollback Oracle v0.

Answers the question the specification asks: "can this package lower any counter
on this device?"

The inequality comes from upstream. AOSP ``external/avb`` (``avb-readme.md``,
section "Rollback Protection") states that rollback protection means "having the
device reject an image unless ``rollback_index[n]`` >= ``stored_rollback_index[n]``
for all ``n``", that the device keeps the last seen value in tamper-evident
storage as ``stored_rollback_index[n]``, and that the indexes differ between A/B
slots. AOSP ``avbtool`` requires a chain partition's rollback index location to
be 1 or larger and forbids two chained partitions from sharing one location.

This module applies that inequality. It is a comparator with provenance, not a
policy engine. No OEM counter policy ships here, because the meaning and the
direction of OEM counters (Xiaomi anti-rollback values, Samsung binary version
and SWREV, fuse-based counters) are device-specific and still unknown
(KU-005, KU-009). A caller that supplies an OEM counter is asserting, with a
source, that a lower number means an older image.

Verdicts are tri-state and fail-closed:

* ``FALSE`` - the package definitely lowers a counter. Never overridable.
* ``UNKNOWN`` - the package may lower a counter and the stored value is unknown.
  This is a hard stop, not a warning.
* ``TRUE`` - the package cannot lower any counter that was evaluated.

The device's stored value is authoritative when it can be read, because the
bootloader compares against the device. A catalog bound is a fallback that is
only consulted when the device value is unknown: an upper bound can prove the
package is safe, and a lower bound can prove the package lowers the counter.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from cairn.core.errors import ConfigurationError
from cairn.core.tristate import Tri
from cairn.provenance.avb import VbmetaImage


class RollbackError(ConfigurationError):
    code = "ROLLBACK_ERROR"


MAX_ROLLBACK_INDEX = (1 << 64) - 1


class CounterKind(StrEnum):
    """What kind of counter a rollback check is about."""

    AVB = "avb"
    OEM = "oem"


@dataclass(frozen=True, slots=True)
class RollbackCounter:
    """One counter that the package must not lower.

    ``package_value`` is the number the package carries. ``stored_value`` is the
    number the device currently enforces; ``None`` means it could not be read,
    which is UNKNOWN rather than safe. ``catalog_minimum`` and
    ``catalog_maximum`` bound the stored value when the device value is
    unavailable; both are only consulted in that case.
    """

    name: str
    kind: CounterKind
    package_value: int
    stored_value: int | None = None
    location: int | None = None
    slot: str | None = None
    source: str = "unknown"
    stored_source: str = "unknown"
    catalog_minimum: int | None = None
    catalog_maximum: int | None = None

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise RollbackError("counter name must not be empty")
        if not self.source.strip():
            raise RollbackError("counter source must not be empty")
        if not self.stored_source.strip():
            raise RollbackError("counter stored source must not be empty")
        if self.package_value < 0:
            raise RollbackError(f"counter {self.name!r} has a negative package value")
        if self.package_value > MAX_ROLLBACK_INDEX:
            raise RollbackError(f"counter {self.name!r} exceeds the 64-bit rollback index limit")
        if self.stored_value is not None and self.stored_value < 0:
            raise RollbackError(f"counter {self.name!r} has a negative stored value")
        if self.stored_value is not None and self.stored_value > MAX_ROLLBACK_INDEX:
            raise RollbackError(f"counter {self.name!r} exceeds the 64-bit rollback index limit")
        if self.stored_value is not None and self.stored_source == "unknown":
            raise RollbackError(f"counter {self.name!r} has a stored value without a stored source")
        if self.stored_value is None and self.stored_source != "unknown":
            raise RollbackError(f"counter {self.name!r} has a stored source without a stored value")
        if self.location is not None and self.location < 0:
            raise RollbackError(f"counter {self.name!r} has a negative location")
        for bound_name, bound in (
            ("catalog minimum", self.catalog_minimum),
            ("catalog maximum", self.catalog_maximum),
        ):
            if bound is not None and bound < 0:
                raise RollbackError(f"counter {self.name!r} has a negative {bound_name}")
            if bound is not None and bound > MAX_ROLLBACK_INDEX:
                raise RollbackError(
                    f"counter {self.name!r} {bound_name} exceeds the 64-bit rollback index limit"
                )
        if (
            self.catalog_minimum is not None
            and self.catalog_maximum is not None
            and self.catalog_minimum > self.catalog_maximum
        ):
            raise RollbackError(f"counter {self.name!r} has a catalog minimum above its maximum")


@dataclass(frozen=True, slots=True)
class OtaDowngradeSignal:
    """OTA metadata that may indicate a downgrade.

    The v0 oracle cannot interpret OTA downgrade metadata against a device, so
    a supplied signal keeps the verdict at UNKNOWN instead of letting the oracle
    claim the package is safe.
    """

    detail: str
    source: str = "ota:metadata"

    def __post_init__(self) -> None:
        if not self.detail.strip():
            raise RollbackError("OTA downgrade signal detail must not be empty")


@dataclass(frozen=True, slots=True)
class RollbackFinding:
    """The verdict for one counter."""

    counter: str
    kind: CounterKind
    state: Tri
    reason: str
    package_value: int | None
    stored_value: int | None
    location: int | None
    slot: str | None
    source: str
    stored_source: str
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "counter": self.counter,
            "kind": self.kind.value,
            "state": self.state.name,
            "reason": self.reason,
            "package_value": self.package_value,
            "stored_value": self.stored_value,
            "location": self.location,
            "slot": self.slot,
            "source": self.source,
            "stored_source": self.stored_source,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class RollbackReport:
    """The overall verdict plus the per-counter findings behind it."""

    state: Tri
    reasons: tuple[str, ...]
    findings: tuple[RollbackFinding, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def blocks(self) -> bool:
        """Whether this verdict prevents proceeding without a catalog proof."""
        return self.state.blocks

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state.name,
            "blocks": self.blocks,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class RollbackInputs:
    """Counters extracted from a package, plus the ones that could not be read."""

    counters: tuple[RollbackCounter, ...] = ()
    unresolved: tuple[str, ...] = ()


def avb_rollback_inputs(
    image: VbmetaImage,
    chain: Mapping[str, VbmetaImage] | None = None,
    *,
    slot: str | None = None,
    stored: Mapping[int, int] | None = None,
    stored_source: str = "device",
    max_depth: int = 8,
    catalog_bounds: Mapping[int, tuple[int | None, int | None]] | None = None,
) -> RollbackInputs:
    """Extract the rollback counters a VBMeta package declares.

    The top-level image contributes the counter at its own rollback index
    location. Each chain descriptor contributes a counter at the location named
    by the descriptor, carrying the rollback index of the chained image, because
    AOSP defines the chained partition's location in the descriptor rather than
    in the chained header. Nested chain descriptors are followed with a depth
    limit. A chained partition whose image was not supplied, or whose descriptor
    is malformed, is reported as unresolved instead of being skipped, so it
    cannot be silently treated as safe.

    ``catalog_bounds`` maps a rollback index location to a caller-cited
    (minimum, maximum) pair for the stored value; a bound is consulted only
    when the device's stored value is unavailable.
    """
    if max_depth < 1:
        raise RollbackError("max_depth must be positive")

    counters: list[RollbackCounter] = []
    unresolved: list[str] = []

    def _bounds(location: int | None) -> tuple[int | None, int | None] | None:
        if catalog_bounds is None or location is None:
            return None
        return catalog_bounds.get(location)

    header = image.header
    main_stored = _stored_value(stored, header.rollback_index_location)
    main_bounds = _bounds(header.rollback_index_location)
    counters.append(
        RollbackCounter(
            name="avb:main",
            kind=CounterKind.AVB,
            package_value=header.rollback_index,
            stored_value=main_stored,
            location=header.rollback_index_location,
            slot=slot,
            source="avb:vbmeta header",
            stored_source=_stored_source(main_stored, stored_source),
            catalog_minimum=None if main_bounds is None else main_bounds[0],
            catalog_maximum=None if main_bounds is None else main_bounds[1],
        )
    )

    _collect_chain_counters(
        image,
        chain or {},
        counters,
        unresolved,
        slot=slot,
        stored=stored,
        stored_source=stored_source,
        visited=frozenset(),
        depth=0,
        max_depth=max_depth,
        catalog_bounds=catalog_bounds,
    )

    return RollbackInputs(counters=tuple(counters), unresolved=tuple(unresolved))


def _collect_chain_counters(
    image: VbmetaImage,
    chain: Mapping[str, VbmetaImage],
    counters: list[RollbackCounter],
    unresolved: list[str],
    *,
    slot: str | None,
    stored: Mapping[int, int] | None,
    stored_source: str,
    visited: frozenset[str],
    depth: int,
    max_depth: int,
    catalog_bounds: Mapping[int, tuple[int | None, int | None]] | None = None,
) -> None:
    for descriptor in image.chain_partitions:
        name = f"avb:{descriptor.partition_name}"
        if depth >= max_depth:
            unresolved.append(name)
            continue
        if descriptor.partition_name in visited:
            unresolved.append(name)
            continue
        if descriptor.rollback_index_location == 0:
            unresolved.append(name)
            continue
        chained = chain.get(descriptor.partition_name)
        if chained is None:
            unresolved.append(name)
            continue
        if chained.header.rollback_index_location != 0:
            unresolved.append(name)
            continue

        chained_stored = _stored_value(stored, descriptor.rollback_index_location)
        bounds = (
            None
            if catalog_bounds is None
            else catalog_bounds.get(descriptor.rollback_index_location)
        )
        counters.append(
            RollbackCounter(
                name=name,
                kind=CounterKind.AVB,
                package_value=chained.header.rollback_index,
                stored_value=chained_stored,
                location=descriptor.rollback_index_location,
                slot=slot,
                source=f"avb:chain descriptor {descriptor.partition_name}",
                stored_source=_stored_source(chained_stored, stored_source),
                catalog_minimum=None if bounds is None else bounds[0],
                catalog_maximum=None if bounds is None else bounds[1],
            )
        )

        if not chained.chain_partitions:
            continue
        _collect_chain_counters(
            chained,
            chain,
            counters,
            unresolved,
            slot=slot,
            stored=stored,
            stored_source=stored_source,
            visited=visited | {descriptor.partition_name},
            depth=depth + 1,
            max_depth=max_depth,
            catalog_bounds=catalog_bounds,
        )


def evaluate_rollback(
    counters: Iterable[RollbackCounter],
    *,
    unresolved: Sequence[str] = (),
    ota: OtaDowngradeSignal | None = None,
) -> RollbackReport:
    """Compare package counters with stored values and return a tri-state verdict.

    An empty evaluation is UNKNOWN, not TRUE: a verdict that says "no counter can
    be lowered" must be backed by at least one evaluated counter.
    """
    findings: list[RollbackFinding] = [_evaluate_counter(counter) for counter in counters]

    for name in unresolved:
        findings.append(
            RollbackFinding(
                counter=name,
                kind=CounterKind.AVB,
                state=Tri.UNKNOWN,
                reason="the rollback index of this chained partition could not be read",
                package_value=None,
                stored_value=None,
                location=None,
                slot=None,
                source="avb:chain descriptor",
                stored_source="unknown",
            )
        )

    if ota is not None:
        findings.append(
            RollbackFinding(
                counter="ota:metadata",
                kind=CounterKind.OEM,
                state=Tri.UNKNOWN,
                reason=f"OTA downgrade metadata cannot be evaluated yet ({ota.detail})",
                package_value=None,
                stored_value=None,
                location=None,
                slot=None,
                source=ota.source,
                stored_source="unknown",
            )
        )

    if not findings:
        return RollbackReport(
            state=Tri.UNKNOWN,
            reasons=("no rollback counters were evaluated",),
            findings=(),
        )

    state = Tri.all_of(finding.state for finding in findings)
    reasons = tuple(f"{finding.counter}: {finding.reason}" for finding in findings)
    warnings = tuple(warning for finding in findings for warning in finding.warnings)
    return RollbackReport(state=state, reasons=reasons, findings=tuple(findings), warnings=warnings)


def evaluate_avb_rollback(
    image: VbmetaImage,
    chain: Mapping[str, VbmetaImage] | None = None,
    *,
    slot: str | None = None,
    stored: Mapping[int, int] | None = None,
    stored_source: str = "device",
    ota: OtaDowngradeSignal | None = None,
    catalog_bounds: Mapping[int, tuple[int | None, int | None]] | None = None,
) -> RollbackReport:
    """Evaluate the rollback counters declared by a VBMeta package."""
    inputs = avb_rollback_inputs(
        image,
        chain,
        slot=slot,
        stored=stored,
        stored_source=stored_source,
        catalog_bounds=catalog_bounds,
    )
    return evaluate_rollback(inputs.counters, unresolved=inputs.unresolved, ota=ota)


def _evaluate_counter(counter: RollbackCounter) -> RollbackFinding:
    stored = counter.stored_value
    package = counter.package_value

    if stored is not None:
        warnings: tuple[str, ...] = ()
        if counter.catalog_maximum is not None and stored > counter.catalog_maximum:
            warnings = (
                f"the stored index {stored} is above the catalog maximum {counter.catalog_maximum}",
            )
        elif counter.catalog_minimum is not None and stored < counter.catalog_minimum:
            warnings = (
                f"the stored index {stored} is below the catalog minimum {counter.catalog_minimum}",
            )
        if package < stored:
            return RollbackFinding(
                counter=counter.name,
                kind=counter.kind,
                state=Tri.FALSE,
                reason=(
                    f"the package index {package} is below the stored index {stored} "
                    f"({counter.stored_source})"
                ),
                package_value=package,
                stored_value=stored,
                location=counter.location,
                slot=counter.slot,
                source=counter.source,
                stored_source=counter.stored_source,
                warnings=warnings,
            )
        return RollbackFinding(
            counter=counter.name,
            kind=counter.kind,
            state=Tri.TRUE,
            reason=(
                f"the package index {package} is at least the stored index {stored} "
                f"({counter.stored_source})"
            ),
            package_value=package,
            stored_value=stored,
            location=counter.location,
            slot=counter.slot,
            source=counter.source,
            stored_source=counter.stored_source,
            warnings=warnings,
        )

    if counter.catalog_maximum is not None and package >= counter.catalog_maximum:
        return RollbackFinding(
            counter=counter.name,
            kind=counter.kind,
            state=Tri.TRUE,
            reason=(
                f"the catalog proves the stored index is at most "
                f"{counter.catalog_maximum} and the package index {package} is not lower"
            ),
            package_value=package,
            stored_value=None,
            location=counter.location,
            slot=counter.slot,
            source=counter.source,
            stored_source=counter.stored_source,
        )

    if counter.catalog_minimum is not None and package < counter.catalog_minimum:
        return RollbackFinding(
            counter=counter.name,
            kind=counter.kind,
            state=Tri.FALSE,
            reason=(
                f"the catalog proves the stored index is at least "
                f"{counter.catalog_minimum} and the package index {package} is lower"
            ),
            package_value=package,
            stored_value=None,
            location=counter.location,
            slot=counter.slot,
            source=counter.source,
            stored_source=counter.stored_source,
        )

    return RollbackFinding(
        counter=counter.name,
        kind=counter.kind,
        state=Tri.UNKNOWN,
        reason="the stored index is unknown, so the package may lower it",
        package_value=package,
        stored_value=None,
        location=counter.location,
        slot=counter.slot,
        source=counter.source,
        stored_source=counter.stored_source,
    )


def _stored_value(stored: Mapping[int, int] | None, location: int) -> int | None:
    if stored is None:
        return None
    return stored.get(location)


def _stored_source(value: int | None, source: str) -> str:
    if value is None:
        return "unknown"
    return source
