"""Pointwise complex-event matching engine (Python standard library + SQLite).

Public API::

    from cep import Engine
    eng = Engine(db, pattern, W)
    eng.apply(rows)  -> {"add": [...], "remove": [...]}
    eng.read()       -> [[key, [id, ...]], ...]

Pattern language (``pattern`` is a type name or a nested array)::

    "A"               one live event of type A
    ["seq", p, q]     a p-match followed by a q-match
    ["or", p, q]      a p-match or a q-match
    ["plus", p]       one or more successive p-matches
    ["not", T, p]     a p-match whose span contains no live event of type T

Input rows are ``[id, rev, key, t, type, deleted]``.  ``id``/``key``/``type``
are strings, ``rev`` a positive integer, ``t`` an integer, ``deleted`` a
bool; ids are unique inside one batch and ``W`` is a non-negative integer.

Matching semantics
------------------
Live events of one key are matched in strictly increasing ``(t, id)`` order.
Events may be skipped.  The span of a match runs from its first to its last
matched event; the head-to-tail time difference must be ``<= W``.  Matches
are identified by their ordered id sequence, so equivalent derivations of the
same sequence are stored once.  ``not`` excludes an event of the named type
whose position in the key's ``(t, id)`` order lies strictly between the head
and the tail of the p-match; the head and tail positions themselves are not
excluded.

Persistence and incrementality
------------------------------
The highest revision of every id lives in ``cep_events`` and the current
match set in ``cep_matches``, in the SQLite database handed to the engine.
Both are written in one transaction per apply, so state and matches commit or
roll back together and reopening the database resumes exactly where it left
off.

An apply never re-examines untouched keys.  For a touched key it examines only
the neighbourhood of the changed positions: every match whose span meets a
changed position has its head within ``W`` of that position, so matches whose
span misses the changed interval are reused verbatim, and only events inside
that interval (fetched with bounded key/``t`` range queries) take part in
re-derivation.  Changed positions farther apart than ``W`` cannot belong to
one match and are processed as independent clusters.
"""

import json
import sqlite3

INPUT = "INVALID"
PATTERN = "PATTERN"
REVISION_CONFLICT = "REVISION_CONFLICT"
CONFIG_CONFLICT = "CONFIG_CONFLICT"

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS cep_meta("
    "k TEXT PRIMARY KEY, v TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS cep_events("
    "id TEXT PRIMARY KEY, rev TEXT NOT NULL, key TEXT NOT NULL,"
    "t TEXT NOT NULL, type TEXT NOT NULL,"
    "deleted INTEGER NOT NULL, body TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS cep_events_key_t ON cep_events(key, t, id)",
    "CREATE TABLE IF NOT EXISTS cep_matches("
    "key TEXT NOT NULL, ids TEXT NOT NULL, first_t TEXT NOT NULL,"
    "last_t TEXT NOT NULL, PRIMARY KEY(key, ids))",
    "CREATE INDEX IF NOT EXISTS cep_matches_span "
    "ON cep_matches(key, first_t, last_t)",
)


_TIME_WIDTH = 8
_TIME_MAX_LENGTH = 10 ** _TIME_WIDTH - 1


def encode_t(value):
    """Order-preserving textual encoding of an arbitrary Python integer.

    SQLite INTEGER columns hold signed 64-bit values only, while event times
    are unbounded Python integers.  This encoding sorts exactly like the
    integers it encodes, so SQLite's lexicographic ordering and range
    comparisons stay faithful; only inputs with more than 99,999,999 decimal
    digits (far beyond any addressable input) would be rejected.
    """
    digits = str(abs(value))
    if len(digits) > _TIME_MAX_LENGTH:
        raise ValueError(INPUT)
    width = len(digits)
    if value >= 0:
        return "1%0*d%s" % (_TIME_WIDTH, width, digits)
    complement = "".join(str(9 - int(digit)) for digit in digits)
    return "0%0*d%s" % (_TIME_WIDTH, _TIME_MAX_LENGTH - width, complement)


def decode_t(value):
    """Inverse of encode_t."""
    marker, width = value[0], int(value[1:1 + _TIME_WIDTH])
    digits = value[1 + _TIME_WIDTH:]
    if marker == "1":
        return int(digits)
    return -int("".join(str(9 - int(digit)) for digit in digits))


def canonical(value):
    """Canonical JSON for persisted content and canonical comparisons."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


# ---------------------------------------------------------------------------
# pattern parsing
# ---------------------------------------------------------------------------

def parse_pattern(pattern):
    """Validate a pattern and normalise it into immutable tuples."""
    if isinstance(pattern, str):
        return ("type", pattern)
    if isinstance(pattern, (list, tuple)) and pattern:
        head = pattern[0]
        rest = list(pattern[1:])
        if head == "seq" and len(rest) == 2:
            return ("seq", parse_pattern(rest[0]), parse_pattern(rest[1]))
        if head == "or" and len(rest) == 2:
            return ("or", parse_pattern(rest[0]), parse_pattern(rest[1]))
        if head == "plus" and len(rest) == 1:
            return ("plus", parse_pattern(rest[0]))
        if head == "not" and len(rest) == 2 and isinstance(rest[0], str):
            return ("not", rest[0], parse_pattern(rest[1]))
    raise ValueError(PATTERN)


def pattern_json(node):
    """Render a parsed pattern back to its document form."""
    kind = node[0]
    if kind == "type":
        return node[1]
    if kind in ("seq", "or"):
        return [kind, pattern_json(node[1]), pattern_json(node[2])]
    if kind == "plus":
        return ["plus", pattern_json(node[1])]
    return ["not", node[1], pattern_json(node[2])]


# ---------------------------------------------------------------------------
# match derivation over one ordered event region
# ---------------------------------------------------------------------------

def derive_matches(node, events, window):
    """Return the set of matches of ``node`` over ``events``.

    ``events`` is an ordered list of ``(id, t, type)``; a match is the tuple of
    the positions it selects.  Over-wide partials are dropped early because an
    extension can only widen a span, so it can never become a legal match.
    """
    times = [event[1] for event in events]

    def in_window(positions):
        return times[positions[-1]] - times[positions[0]] <= window

    def derive(current):
        kind = current[0]
        if kind == "type":
            name = current[1]
            return {(i,) for i, event in enumerate(events)
                    if event[2] == name}
        if kind == "or":
            return derive(current[1]) | derive(current[2])
        if kind == "seq":
            left, right = derive(current[1]), derive(current[2])
            out = set()
            for head in left:
                last = head[-1]
                first_time = times[head[0]]
                for tail in right:
                    if tail[0] > last:
                        if times[tail[-1]] - first_time <= window:
                            out.add(head + tail)
            return out
        if kind == "plus":
            single = {match for match in derive(current[1])
                      if in_window(match)}
            out = set(single)
            frontier = set(single)
            while frontier:
                grown = set()
                for prefix in frontier:
                    last = prefix[-1]
                    first_time = times[prefix[0]]
                    for tail in single:
                        if tail[0] > last:
                            if times[tail[-1]] - first_time <= window:
                                grown.add(prefix + tail)
                grown -= out
                if not grown:
                    break
                out |= grown
                frontier = grown
            return out
        if kind == "not":
            name = current[1]
            inner = derive(current[2])
            prefix = [0] * (len(events) + 1)
            for i, event in enumerate(events):
                prefix[i + 1] = prefix[i] + (1 if event[2] == name else 0)
            out = set()
            for positions in inner:
                if not in_window(positions):
                    continue
                head, tail = positions[0], positions[-1]
                # Events strictly between the head and the tail: head+1..tail-1
                if tail <= head or prefix[tail] - prefix[head + 1] == 0:
                    out.add(positions)
            return out
        raise ValueError(PATTERN)

    return derive(node)


def _valid_window(value):
    return type(value) is int and value >= 0


# ---------------------------------------------------------------------------
# engine
# ---------------------------------------------------------------------------

class Engine:
    """Revisioned event store with continuously maintained pattern matches."""

    def __init__(self, db, pattern, W):
        node = parse_pattern(pattern)
        if not _valid_window(W):
            raise ValueError(INPUT)
        self.pattern = pattern
        self.pattern_node = node
        self.W = W
        self.window = W
        if isinstance(db, sqlite3.Connection):
            self.conn = db
            self._owns_connection = False
        else:
            self.conn = sqlite3.connect(db, timeout=30)
            self._owns_connection = True
        self.conn.row_factory = sqlite3.Row
        self.conn.isolation_level = None
        self.db = self.conn
        self._config = canonical(
            {"pattern": pattern_json(node), "window": W})
        # Instrumentation used by the verification suite to prove locality.
        self.stats = {"keys_visited": 0, "events_scanned": 0,
                      "matches_rebuilt": 0}
        self._install()

    # -- lifecycle ---------------------------------------------------------
    def _install(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in _SCHEMA:
                self.conn.execute(statement)
            row = self.conn.execute(
                "SELECT v FROM cep_meta WHERE k='config'").fetchone()
            if row is None:
                self.conn.execute(
                    "INSERT INTO cep_meta(k, v) VALUES('config', ?)",
                    (self._config,))
            elif row[0] != self._config:
                raise ValueError(CONFIG_CONFLICT)
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    def close(self):
        if self._owns_connection:
            self.conn.close()
            self._owns_connection = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    # -- validation --------------------------------------------------------
    @staticmethod
    def _validate_rows(rows):
        if not isinstance(rows, (list, tuple)):
            raise ValueError(INPUT)
        seen = set()
        normalised = []
        for row in rows:
            if not isinstance(row, (list, tuple)) or len(row) != 6:
                raise ValueError(INPUT)
            rid, rev, key, t, kind, deleted = row
            if (not isinstance(rid, str) or not isinstance(key, str)
                    or not isinstance(kind, str)
                    or type(rev) is not int or rev <= 0
                    or type(t) is not int or type(deleted) is not bool):
                raise ValueError(INPUT)
            if rid in seen:
                raise ValueError(INPUT)
            seen.add(rid)
            normalised.append((rid, rev, key, t, kind, deleted))
        return normalised

    @staticmethod
    def _live_version(row):
        if row["deleted"]:
            return None
        return (row["id"], row["key"], decode_t(row["t"]), row["type"])

    # -- apply -------------------------------------------------------------
    def apply(self, rows):
        normalised = self._validate_rows(rows)
        added, removed = [], []
        self.stats = {"keys_visited": 0, "events_scanned": 0,
                      "matches_rebuilt": 0}
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            current, accepted = {}, []
            for rid, rev, key, t, kind, deleted in normalised:
                if rid in current:
                    previous = current[rid]
                else:
                    previous = self.conn.execute(
                        "SELECT id, rev, key, t, type, deleted, body "
                        "FROM cep_events WHERE id=?", (rid,)).fetchone()
                    current[rid] = previous
                if previous is not None:
                    previous_rev = int(previous["rev"])
                    if rev < previous_rev:
                        continue
                    if rev == previous_rev:
                        body = canonical([key, str(t), kind, deleted])
                        if body != previous["body"]:
                            raise ValueError(REVISION_CONFLICT)
                        continue
                accepted.append((rid, rev, key, t, kind, deleted, previous))

            if accepted:
                affected = {}
                for rid, rev, key, t, kind, deleted, previous in accepted:
                    old = None if previous is None else self._live_version(
                        previous)
                    new = None if deleted else (rid, key, t, kind)
                    if old is None and new is None:
                        continue
                    if old is not None and new is not None and old == new:
                        continue  # only the revision moved
                    if old is not None:
                        affected.setdefault(old[1], set()).add(old[2])
                    if new is not None:
                        affected.setdefault(new[1], set()).add(new[2])
                for rid, rev, key, t, kind, deleted, _previous in accepted:
                    self.conn.execute(
                        "INSERT INTO cep_events(id, rev, key, t, type, "
                        "deleted, body) VALUES(?,?,?,?,?,?,?) "
                        "ON CONFLICT(id) DO UPDATE SET rev=excluded.rev, "
                        "key=excluded.key, t=excluded.t, "
                        "type=excluded.type, deleted=excluded.deleted, "
                        "body=excluded.body",
                        (rid, str(rev), key, encode_t(t), kind,
                         1 if deleted else 0,
                         canonical([key, str(t), kind, deleted])))
                for key in sorted(affected):
                    adds, removes = self._rebuild_key(key, affected[key])
                    added.extend(adds)
                    removed.extend(removes)
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        return {
            "add": sorted(added, key=lambda entry: (entry[0], entry[1])),
            "remove": sorted(removed, key=lambda entry: (entry[0], entry[1])),
        }

    def _clusters(self, moment_times):
        """Group changed times; a match is at most W wide, so times farther
        apart than W cannot belong to one match."""
        ordered = sorted(moment_times)
        clusters = []
        lo = hi = ordered[0]
        for moment in ordered[1:]:
            if moment - hi > self.W:
                clusters.append((lo, hi))
                lo = hi = moment
            else:
                hi = moment
        clusters.append((lo, hi))
        return clusters

    def _rebuild_key(self, key, moment_times):
        """Update one key's match set, examining only affected neighbourhoods.

        Every match whose span meets a changed position can change, and then
        its head is at most ``W`` before that position and its tail at most
        ``W`` after it, so the match lies inside a bounded window around the
        change.  Matches whose spans miss every change are reused verbatim.
        Changed positions farther apart than ``W`` cannot belong to one match
        and are examined independently.  All stale rows are collected before
        any row is rewritten, because one id sequence may migrate from the
        neighbourhood of one change to that of another.
        """
        self.stats["keys_visited"] += 1
        stale_ids, inserts = [], []
        for lo, hi in self._clusters(moment_times):
            events = self._events_near(key, lo, hi)
            position_ids = [event[0] for event in events]
            times = [event[1] for event in events]

            for row in self.conn.execute(
                    "SELECT ids FROM cep_matches WHERE key=? "
                    "AND last_t>=? AND first_t<=? AND first_t>=?",
                    (key, encode_t(lo), encode_t(hi),
                     encode_t(lo - self.W))).fetchall():
                stale_ids.append(row["ids"])

            for positions in derive_matches(self.pattern_node, events, self.W):
                first_t, last_t = times[positions[0]], times[positions[-1]]
                # Only spans meeting this cluster's changes can differ here;
                # neighbouring untouched matches are reused, not re-derived.
                if first_t > hi or last_t < lo:
                    continue
                ids = [position_ids[position] for position in positions]
                inserts.append((canonical(ids), encode_t(first_t),
                                encode_t(last_t)))

        old_ids = set(stale_ids)
        new_ids = {packed for packed, _first, _last in inserts}
        fresh = [(key, packed, first_t, last_t)
                 for packed, first_t, last_t in inserts]

        if stale_ids:
            self.conn.executemany(
                "DELETE FROM cep_matches WHERE key=? AND ids=?",
                [(key, packed) for packed in stale_ids])
        if fresh:
            self.conn.executemany(
                "INSERT OR REPLACE INTO cep_matches(key, ids, first_t, "
                "last_t) VALUES(?,?,?,?)", fresh)
        self.stats["matches_rebuilt"] += len(fresh)

        added = [[key, json.loads(packed)] for packed in new_ids - old_ids]
        removed = [[key, json.loads(packed)] for packed in old_ids - new_ids]
        return added, removed

    def _events_near(self, key, lo, hi):
        """Live events of ``key`` that an affected match around [lo, hi] may use.

        A match touching [lo, hi] has its first event at most ``W`` before it
        and its last event at most ``W`` after it; intermediate events lie in
        between, so this single bounded range covers everything it needs.
        """
        rows = self.conn.execute(
            "SELECT id, t, type FROM cep_events WHERE key=? "
            "AND deleted=0 AND t>=? AND t<=?",
            (key, encode_t(lo - self.W), encode_t(hi + self.W))).fetchall()
        self.stats["events_scanned"] += len(rows)
        events = [(row["id"], decode_t(row["t"]), row["type"]) for row in rows]
        return sorted(events, key=lambda event: (event[1], event[0]))

    # -- read --------------------------------------------------------------
    def read(self):
        rows = self.conn.execute(
            "SELECT key, ids FROM cep_matches").fetchall()
        result = [[row["key"], json.loads(row["ids"])] for row in rows]
        return sorted(result, key=lambda entry: (entry[0], entry[1]))
