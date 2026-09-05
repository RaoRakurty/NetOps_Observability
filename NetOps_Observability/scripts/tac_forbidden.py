"""tac_forbidden.py — the OUTPUT-ONLY command policy, Python side.

Owner decision, 2026-09-05: a command that changes configuration, that restarts
or reboots, or that touches a daemon must not merely be refused — it must not be
KNOWN to Correlix at all. `src/backend/ai/tac/forbidden.yaml` is that vocabulary
as data; this module is the matcher two scripts share:

    scripts/tac-merge-research.py    refuses a forbidden record AT THE DOOR and
                                     reports only a count per family
    scripts/tac-purge-forbidden.py   removes every forbidden record that is
                                     already in the corpus, and keeps the census

The Go side (`src/backend/internal/tac/forbidden.go`) implements the SAME
matcher over the SAME file, and `internal/tac`'s own tests plus
`tests/test_tac_forbidden_policy.py` prove the two agree on the shipped data.

Matching is on COMMAND TOKENS, never on substrings: a rule's tokens must be the
command's LEADING tokens. `reload` therefore refuses `reload in 5` and leaves
`show reload cause` alone — which is the distinction the whole policy rests on.

Standard library only (CLAUDE.md §6). It takes an already-parsed document rather
than parsing YAML itself, so there is exactly one YAML reader on this side.
"""

from __future__ import annotations

FAMILIES = ("config", "restart", "daemon")
READ_LEADS = frozenset({"show", "display", "get", "info"})


class PolicyError(Exception):
    """A malformed policy file. It is a hard stop: a policy that does not load
    is a policy that is not enforced, and the failure must be loud."""


def _tokens(value: object, what: str) -> list[str]:
    toks = str(value or "").lower().split()
    if not toks:
        raise PolicyError(f"{what}: names no tokens")
    return toks


def _has_prefix(toks: list[str], prefix: list[str]) -> bool:
    return len(prefix) > 0 and len(toks) >= len(prefix) and toks[: len(prefix)] == prefix


class Rule:
    """One entry of the vocabulary Correlix refuses to learn."""

    __slots__ = ("dialect", "exceptions", "family", "tokens", "why")

    def __init__(self, family: str, dialect: str, tokens: list[str], why: str,
                 exceptions: list[list[str]]) -> None:
        self.family = family
        self.dialect = dialect
        self.tokens = tokens
        self.why = why
        self.exceptions = exceptions

    def __str__(self) -> str:
        return " ".join(self.tokens)

    def matches(self, toks: list[str]) -> bool:
        if not _has_prefix(toks, self.tokens):
            return False
        return not any(_has_prefix(toks, exc) for exc in self.exceptions)


class SessionScope:
    """A setter that narrows what a READ prints and dies with the CLI session.
    It changes no configuration and clears nothing, so the owner's rule does not
    bite — provided the plan carries the matching teardown."""

    __slots__ = ("dialect", "teardown", "tokens", "why")

    def __init__(self, dialect: str, tokens: list[str], teardown: str, why: str) -> None:
        self.dialect = dialect
        self.tokens = tokens
        self.teardown = teardown
        self.why = why


class Policy:
    """The compiled forbidden vocabulary."""

    def __init__(self, version: str) -> None:
        self.version = version
        self.common: list[Rule] = []
        self.by_dialect: dict[str, list[Rule]] = {}
        self.scopes: dict[str, list[SessionScope]] = {}
        self.census: dict = {}

    # ── matching ────────────────────────────────────────────────────────────

    def match(self, dialect: str, command: str):
        """Return the Rule `command` hits on `dialect`, or None.

        Longest rule wins; a DIALECT rule beats a common rule of the same
        length, so a vendor may name the family its own spelling belongs to. An
        UNKNOWN dialect still gets the common rules — the policy is never
        narrower for a platform Correlix does not recognise.
        """
        toks = str(command or "").lower().split()
        if not toks:
            return None
        best = None
        for rule in list(self.by_dialect.get(dialect, [])) + self.common:
            if not rule.matches(toks):
                continue
            if best is None or len(rule.tokens) > len(best.tokens):
                best = rule
        return best

    def session_scope(self, dialect: str, command: str):
        """Return the SessionScope `command` is a setter for, or None."""
        toks = str(command or "").lower().split()
        for scope in self.scopes.get(dialect, []):
            if _has_prefix(toks, scope.tokens):
                return scope
        return None

    def rules(self) -> list[Rule]:
        out = list(self.common)
        for dialect in sorted(self.by_dialect):
            out += self.by_dialect[dialect]
        return out


def _load_rules(block: object, dialect: str, what: str) -> list[Rule]:
    out: list[Rule] = []
    seen: set[tuple[str, str]] = set()
    for raw in block or []:
        if not isinstance(raw, dict):
            raise PolicyError(f"{what}: a rule must be a mapping, got {raw!r}")
        unknown = sorted(set(raw) - {"family", "tokens", "why", "except"})
        if unknown:
            raise PolicyError(f"{what}: unknown field(s) in a rule: {', '.join(unknown)}")
        family = str(raw.get("family", "")).strip()
        if family not in FAMILIES:
            raise PolicyError(f"{what}: family {family!r} is outside the closed set {FAMILIES}")
        tokens = _tokens(raw.get("tokens"), what)
        if tokens[0] in READ_LEADS:
            raise PolicyError(
                f"{what}: rule {' '.join(tokens)!r} begins with a read verb; "
                "the policy may never refuse an output command")
        why = str(raw.get("why", "")).strip()
        if not why:
            raise PolicyError(f"{what}: rule {' '.join(tokens)!r} says nothing about why")
        exceptions: list[list[str]] = []
        for exc in raw.get("except") or []:
            etoks = str(exc).lower().split()
            if len(etoks) <= len(tokens) or not _has_prefix(etoks, tokens):
                raise PolicyError(
                    f"{what}: exception {exc!r} is not a longer form of the rule "
                    f"{' '.join(tokens)!r} it belongs to")
            exceptions.append(etoks)
        key = (family, " ".join(tokens))
        if key in seen:
            raise PolicyError(f"{what}: rule {' '.join(tokens)!r} is declared twice")
        seen.add(key)
        out.append(Rule(family, dialect, tokens, why, exceptions))
    return out


def load_policy(doc: object) -> Policy:
    """Compile an already-parsed forbidden.yaml document."""
    if not isinstance(doc, dict):
        raise PolicyError("forbidden.yaml: document must be a mapping")
    unknown = sorted(set(doc) - {"schema_version", "version", "families", "sources",
                                 "common", "dialects", "session_scoped", "census"})
    if unknown:
        raise PolicyError(f"forbidden.yaml: unknown top-level field(s): {', '.join(unknown)}")
    if str(doc.get("schema_version", "")).strip() != "1":
        raise PolicyError("forbidden.yaml: `schema_version: 1` is required")
    version = str(doc.get("version", "")).strip()
    if not version:
        raise PolicyError("forbidden.yaml: `version` is required")
    declared = [str(f.get("id", "")).strip() for f in doc.get("families") or []
                if isinstance(f, dict)]
    if sorted(declared) != sorted(FAMILIES):
        raise PolicyError(
            "forbidden.yaml: `families` must declare exactly the owner's three "
            f"({', '.join(FAMILIES)}), got {declared}")

    pol = Policy(version)
    pol.common = _load_rules(doc.get("common"), "", "forbidden.yaml common")
    if not pol.common:
        raise PolicyError("forbidden.yaml: `common` is required")
    for entry in doc.get("dialects") or []:
        if not isinstance(entry, dict):
            raise PolicyError("forbidden.yaml: a dialect policy must be a mapping")
        unknown = sorted(set(entry) - {"dialect", "sources", "rules"})
        if unknown:
            raise PolicyError(f"forbidden.yaml: unknown field(s) in a dialect policy: {', '.join(unknown)}")
        slug = str(entry.get("dialect", "")).strip()
        if not slug:
            raise PolicyError("forbidden.yaml: a dialect policy names no dialect")
        if slug in pol.by_dialect:
            raise PolicyError(f"forbidden.yaml: dialect {slug!r} appears twice")
        if not entry.get("sources"):
            raise PolicyError(
                f"forbidden.yaml: dialect {slug!r} names no `sources` — a per-vendor "
                "rule must cite the vendor's own reference")
        rules = _load_rules(entry.get("rules"), slug, f"forbidden.yaml dialect {slug}")
        if not rules:
            raise PolicyError(f"forbidden.yaml: dialect {slug!r} carries no rules")
        pol.by_dialect[slug] = rules

    for entry in doc.get("session_scoped") or []:
        if not isinstance(entry, dict):
            raise PolicyError("forbidden.yaml: a session-scoped setter must be a mapping")
        unknown = sorted(set(entry) - {"dialect", "tokens", "teardown", "why", "sources"})
        if unknown:
            raise PolicyError(f"forbidden.yaml: unknown field(s) in a session-scoped setter: {', '.join(unknown)}")
        slug = str(entry.get("dialect", "")).strip()
        tokens = _tokens(entry.get("tokens"), "forbidden.yaml session_scoped")
        teardown = " ".join(str(entry.get("teardown", "")).split())
        td = teardown.lower().split()
        if len(td) != len(tokens) + 1 or not _has_prefix(td, tokens):
            raise PolicyError(
                f"forbidden.yaml: teardown {teardown!r} is not {' '.join(tokens)!r} "
                "plus one terminating verb")
        if td[-1] not in {"clear", "reset", "flush", "none"}:
            raise PolicyError(f"forbidden.yaml: teardown {teardown!r} must end in clear/reset/flush/none")
        why = str(entry.get("why", "")).strip()
        if not why:
            raise PolicyError(f"forbidden.yaml: session-scoped setter {teardown!r} says nothing about why")
        if not entry.get("sources"):
            raise PolicyError(
                f"forbidden.yaml: session-scoped setter {' '.join(tokens)!r} carries no "
                "`sources` — an exemption from the owner's rule must cite the page that establishes it")
        pol.scopes.setdefault(slug, []).append(SessionScope(slug, tokens, teardown, why))

    census = doc.get("census")
    if not isinstance(census, dict):
        raise PolicyError("forbidden.yaml: `census` is required")
    pol.census = census
    return pol


def empty_counts() -> dict:
    """A zeroed per-family tally, in report order."""
    return {family: 0 for family in FAMILIES}


# ── the one thing that IS allowed: a bounded reachability probe ──────────────
#
# Owner, 2026-09-05: "Ping and traceroute are good examples, should be allowed."
# This mirrors src/backend/internal/protocoldiag/probe.go token for token and
# bound for bound; tests/test_tac_forbidden_policy.py proves the two agree.

MAX_PROBE_COUNT = 5
MAX_PROBE_SIZE = 1500
MAX_PROBE_TIMEOUT_S = 5
MAX_PROBE_HOPS = 30
MAX_PROBE_PROBES = 3
MAX_PROBE_TOKENS = 16

PROBE_LEAD = frozenset({"ping", "ping6", "traceroute", "traceroute6"})

PROBE_NUMERIC_KEYWORD = {
    "count": MAX_PROBE_COUNT, "repeat": MAX_PROBE_COUNT, "-c": MAX_PROBE_COUNT,
    "ntimes": MAX_PROBE_COUNT,
    "size": MAX_PROBE_SIZE, "packet-size": MAX_PROBE_SIZE, "datalen": MAX_PROBE_SIZE,
    "data-size": MAX_PROBE_SIZE, "-s": MAX_PROBE_SIZE,
    "timeout": MAX_PROBE_TIMEOUT_S, "wait-time": MAX_PROBE_TIMEOUT_S, "-w": MAX_PROBE_TIMEOUT_S,
    "ttl": MAX_PROBE_HOPS, "hop-limit": MAX_PROBE_HOPS, "max-hops": MAX_PROBE_HOPS,
    "maximum-hops": MAX_PROBE_HOPS, "first-ttl": MAX_PROBE_HOPS, "-m": MAX_PROBE_HOPS,
    "probe": MAX_PROBE_PROBES, "probes": MAX_PROBE_PROBES, "queries": MAX_PROBE_PROBES,
    "-q": MAX_PROBE_PROBES,
}

PROBE_ARG_KEYWORD = frozenset({
    "host", "source", "source-address", "source-interface", "source-ip", "-a",
    "interface", "egress", "vrf", "vpn-instance", "instance", "routing-instance",
    "network-instance", "vdom", "vsys", "logical-router", "virtual-router",
})

# The arg-taking keywords whose argument is the DESTINATION rather than a source
# or a routing context.
PROBE_DEST_KEYWORD = frozenset({"host"})

PROBE_FLAG = frozenset({
    "df-bit", "do-not-fragment", "donotfragment", "dont-fragment",
    "numeric", "no-resolve", "brief", "detail",
    "inet", "inet6", "ipv4", "ipv6", "ip",
})

PROBE_BANNED = frozenset({
    "flood", "-f", "sweep", "sweep-min", "sweep-max", "sweep-incr", "rapid",
    "pattern", "data-pattern", "continuous", "infinite", "-t", "interval", "-i",
    "adaptive", "validate", "bypass-routing", "loose-source", "strict-source",
    "record-route", "verbose",
})

PROBE_METACHARS = (";", "\n", "\r", "&", "`", "$(", "${", ">", "<", "!", "|")


class ProbeRefusal(Exception):
    """A probe outside the bounds. It is reported with its reason, like any
    other refusal — the command is real, and Correlix will not run it as written."""


def is_probe_command(command: str) -> bool:
    """Whether `command` LEADS like a bounded probe (says nothing about bounds)."""
    toks = str(command or "").split()
    if toks and toks[0].lower() == "execute":
        toks = toks[1:]
    return bool(toks) and toks[0].lower() in PROBE_LEAD


def _probe_arg_ok(tok: str) -> bool:
    if tok.startswith("{") and tok.endswith("}"):
        return True
    if not tok or len(tok) > 128:
        return False
    return all(ch.isalnum() or ch in "._:/+@,%[]-" for ch in tok)


def validate_bounded_probe(command: str) -> str:
    """Return the normalised probe, or raise ProbeRefusal naming what is wrong."""
    cmd = " ".join(str(command or "").split())
    if not cmd:
        raise ProbeRefusal("empty command")
    for bad in PROBE_METACHARS:
        if bad in cmd:
            raise ProbeRefusal(f"contains the disallowed metacharacter {bad!r}")
    toks = cmd.split()
    if len(toks) > MAX_PROBE_TOKENS:
        raise ProbeRefusal(
            f"carries {len(toks)} tokens, more than the {MAX_PROBE_TOKENS} a bounded probe may")
    if toks[0].lower() == "execute":
        toks = toks[1:]
        if not toks:
            raise ProbeRefusal("`execute` with no probe verb after it")
    if toks[0].lower() not in PROBE_LEAD:
        raise ProbeRefusal(
            f"lead token {toks[0]!r} is not a bounded probe verb ({'/'.join(sorted(PROBE_LEAD))})")
    destinations = 0
    i = 1
    while i < len(toks):
        tok = toks[i]
        lower = tok.lower()
        if lower in PROBE_BANNED:
            raise ProbeRefusal(f"modifier {tok!r} is not permitted on a bounded probe")
        if lower in PROBE_NUMERIC_KEYWORD:
            limit = PROBE_NUMERIC_KEYWORD[lower]
            if i + 1 >= len(toks):
                raise ProbeRefusal(f"{tok!r} carries no value")
            i += 1
            value = toks[i]
            if not value.isdigit() or len(value) > 9:
                raise ProbeRefusal(f"{tok!r} must be followed by a plain number, got {value!r}")
            number = int(value)
            if number < 1 or number > limit:
                raise ProbeRefusal(f"{tok} {value} is outside the bound (1..{limit})")
            i += 1
            continue
        if lower in PROBE_ARG_KEYWORD:
            if i + 1 >= len(toks):
                raise ProbeRefusal(f"{tok!r} carries no value")
            i += 1
            if not _probe_arg_ok(toks[i]):
                raise ProbeRefusal(
                    f"{tok!r} is followed by {toks[i]!r}, which is not an argument-shaped token")
            if lower in PROBE_DEST_KEYWORD:
                # PAN-OS spells the destination `host <addr>`.
                destinations += 1
            i += 1
            continue
        if lower in PROBE_FLAG:
            i += 1
            continue
        if tok.isdigit():
            raise ProbeRefusal(
                f"bare number {tok!r}: a probe's counts and sizes must be written with their keyword")
        if not _probe_arg_ok(tok):
            raise ProbeRefusal(f"token {tok!r} is outside the bounded-probe grammar")
        destinations += 1
        i += 1
    if destinations == 0:
        raise ProbeRefusal(
            "probe names no destination; a bare ping/traceroute opens an interactive "
            "dialog on several platforms")
    return cmd
