"""DirectedTopology — the source-agnostic causal-direction oracle (C7).

Causal direction (§4.3) claims A→B only on a 2-of-3 vote: onset order, **topology
up/down**, OSI layer. This module supplies vote #2. It answers one question —
"is device A upstream of B?" — by fusing directed-direction SOURCES, measured over
inferred (the research finding: leaders derive direction from observed/measured paths,
never from undirected wiring). Design: docs/design/directed-topology-rca.md.

Pure + deterministic + replay-safe: orientation depends only on the registered
sources' data (which a snapshot embeds), never on wall-clock or call order. With NO
sources it returns UNKNOWN for every pair — i.e. vote #2 abstains, exactly today's
behavior — so wiring it in is a safe no-op until a source is fed (C7.3+).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Optional, Protocol


class Verdict(str, Enum):
    A_UPSTREAM = "a_upstream"   # a is upstream of b (traffic/causality candidate a→b)
    B_UPSTREAM = "b_upstream"   # b is upstream of a (b→a)
    AMBIGUOUS = "ambiguous"     # balanced/bidirectional or sources conflict → abstain
    UNKNOWN = "unknown"         # no source covers this pair → abstain


@dataclass(frozen=True)
class Orientation:
    """A directed answer plus its provenance — rendered into the evidence log so a
    claimed direction is always traceable to the source that oriented it."""

    verdict: Verdict
    confidence: float = 0.0
    source: str = ""


# A Source maps an ordered device pair → its confident Orientation, or None when it
# does not cover the pair. Sources are consulted in PRECEDENCE order (measured >
# observed > computed); each must answer for the SAME ordered (a, b) it is given.
Source = Callable[[str, str], Optional[Orientation]]


class Oracle(Protocol):
    """Anything that can orient a device pair — the live DirectedTopology, a frozen
    replay oracle, or a recording wrapper. The engine depends only on this."""

    def orient(self, a: str | None, b: str | None) -> Orientation: ...


@dataclass(frozen=True)
class DirectedTopology:
    """Fuses ordered direction sources. v1 fusion is CONSERVATIVE: every covering
    source must agree, else AMBIGUOUS — we never pick a side on contradicting
    evidence (a precedence-based "trust measured over observed on conflict" refinement
    is deferred; it is a fusion-policy change that needs validation per the
    research-before-implementing rule). UNKNOWN when no source covers the pair."""

    sources: tuple[tuple[str, Source], ...] = ()

    def orient(self, a: str | None, b: str | None) -> Orientation:
        if not a or not b or a == b:
            return Orientation(Verdict.UNKNOWN)
        covering: list[Orientation] = []
        for _name, src in self.sources:
            o = src(a, b)
            if o is not None and o.verdict in (Verdict.A_UPSTREAM, Verdict.B_UPSTREAM):
                covering.append(o)
        if not covering:
            return Orientation(Verdict.UNKNOWN)
        first = covering[0]
        if any(o.verdict != first.verdict for o in covering[1:]):
            return Orientation(Verdict.AMBIGUOUS, source="conflict")
        return first  # all covering sources agree → highest-precedence (first) answer


@dataclass
class RecordingOracle:
    """Wraps an oracle and remembers every CONFIDENT orientation it returned, keyed
    by the ordered pair asked. run_window uses this to capture exactly the directed
    answers an object's edges were built on, so they can be EMBEDDED in the snapshot
    and replayed deterministically (like seams) — direction never depends on live
    state at replay time. Abstentions (UNKNOWN/AMBIGUOUS) are not recorded."""

    inner: Oracle
    calls: dict[tuple[str, str], Orientation] = field(default_factory=dict)

    def orient(self, a: str | None, b: str | None) -> Orientation:
        o = self.inner.orient(a, b)
        if a and b and o.verdict in (Verdict.A_UPSTREAM, Verdict.B_UPSTREAM):
            self.calls[(a, b)] = o
        return o


def frozen_oracle(orientations: Iterable[tuple]) -> DirectedTopology:
    """Build an oracle that returns EMBEDDED orientations verbatim — the replay path.
    Each row = (from_dev, to_dev, verdict_value, source). `orient(a,b)` returns the
    stored verdict for that ordered pair, UNKNOWN otherwise. No live state → a directed
    edge recomputes identically at replay time."""
    table: dict[tuple[str, str], Orientation] = {}
    for frm, to, verdict, source in orientations:
        table[(str(frm), str(to))] = Orientation(Verdict(verdict), source=str(source))

    def _src(a: str, b: str) -> Optional[Orientation]:
        return table.get((a, b))

    return DirectedTopology(sources=(("embedded", _src),))
