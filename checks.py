"""Business verification and demonstration for the pointwise CEP engine.

Run:
    python3 checks.py verify    # business regressions + differential fuzzing
    python3 checks.py demo      # a real acquisition fault-chain walkthrough

The verification deliberately does not reuse the engine's matching code: every
expected result is recomputed from the persisted source rows by
``cep.oracle``, an independent full recomputation.
"""

import json
import os
import random
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cep import Engine, INPUT, PATTERN, REVISION_CONFLICT, CONFIG_CONFLICT
from cep.oracle import oracle


def canon(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def delta(before, after):
    old = {(key, tuple(ids)) for key, ids in before}
    new = {(key, tuple(ids)) for key, ids in after}
    return {
        "add": [[key, list(ids)] for key, ids in sorted(new - old)],
        "remove": [[key, list(ids)] for key, ids in sorted(old - new)],
    }


def expect_error(engine, call, code):
    try:
        call()
    except ValueError as exc:
        assert str(exc) == code, (str(exc), code)
    else:
        raise AssertionError("expected " + code)


def dump(conn):
    """Complete persistent image, used to prove atomic rollback."""
    return list(conn.iterdump())


class Model:
    """Independent revision store.  Ground truth comes from cep.oracle."""

    def __init__(self, pattern, window):
        self.pattern = pattern
        self.window = window
        self.records = {}

    def apply(self, rows):
        if not isinstance(rows, (list, tuple)):
            raise ValueError(INPUT)
        seen = set()
        staged = dict(self.records)
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
        for row in rows:
            rid, rev, key, t, kind, deleted = row
            previous = staged.get(rid)
            if previous is not None:
                if rev < previous[0]:
                    continue
                if rev == previous[0]:
                    if (key, t, kind, deleted) != previous[1:]:
                        raise ValueError(REVISION_CONFLICT)
                    continue
            staged[rid] = (rev, key, t, kind, deleted)
        self.records = staged
        return self.read()

    def read(self):
        return oracle(self.records, self.pattern, self.window)


# ---------------------------------------------------------------------------
# business regressions
# ---------------------------------------------------------------------------

def check_big_numbers():
    big = 10 ** 40
    eng = Engine(":memory:", ["seq", "A", "B"], 2)
    eng.apply([["a", big, "k", -big, "A", False],
               ["b", big, "k", -big + 2, "B", False]])
    assert eng.read() == [["k", ["a", "b"]]]
    eng.apply([["b", big + 1, "k", -big + 2, "B", True]])
    assert eng.read() == []
    # Ordering of huge times is faithful, including negative extremes.
    eng = Engine(":memory:", "A", 0)
    for index, value in enumerate((big, -big, 0, big - 1, -big + 1)):
        eng.apply([["a%d" % index, 1, "k", value, "A", False]])
    assert eng.read() == [
        ["k", ["a0"]], ["k", ["a1"]], ["k", ["a2"]],
        ["k", ["a3"]], ["k", ["a4"]]]


def check_spec_example():
    eng = Engine(":memory:", ["seq", "A", "B"], 2)
    assert eng.apply([["a", 1, "k", 0, "A", False],
                      ["b", 1, "k", 2, "B", False]]) == {
        "add": [["k", ["a", "b"]]], "remove": []}
    assert eng.read() == [["k", ["a", "b"]]]
    # Revoking B removes the whole chain; reviving it restores it.
    assert eng.apply([["b", 2, "k", 2, "B", True]]) == {
        "add": [], "remove": [["k", ["a", "b"]]]}
    assert eng.read() == []
    assert eng.apply([["b", 3, "k", 2, "B", False]]) == {
        "add": [["k", ["a", "b"]]], "remove": []}
    assert eng.read() == [["k", ["a", "b"]]]
    # The window is inclusive at the upper bound and strict beyond it.
    wide = Engine(":memory:", ["seq", "A", "B"], 3)
    wide.apply([["a", 1, "k", 0, "A", False],
                ["b", 1, "k", 3, "B", False]])
    assert wide.read() == [["k", ["a", "b"]]]
    narrow = Engine(":memory:", ["seq", "A", "B"], 2)
    narrow.apply([["a", 1, "k", 0, "A", False],
                  ["b", 1, "k", 3, "B", False]])
    assert narrow.read() == []
    # Time is measured head to tail, not pairwise.
    chain = Engine(":memory:", ["seq", ["seq", "A", "B"], "C"], 4)
    chain.apply([["a", 1, "k", 0, "A", False],
                 ["b", 1, "k", 2, "B", False],
                 ["c", 1, "k", 4, "C", False]])
    assert chain.read() == [["k", ["a", "b", "c"]]]


def check_skipping_and_order():
    eng = Engine(":memory:", ["seq", "A", "B"], 2)
    # An unrelated event may sit between the two matched events.
    eng.apply([["a", 1, "k", 0, "A", False],
               ["x", 1, "k", 1, "X", False],
               ["b", 1, "k", 2, "B", False]])
    assert eng.read() == [["k", ["a", "b"]]]
    # Same time is ordered by id (strictly increasing (t, id)).
    eng = Engine(":memory:", ["seq", "A", "B"], 2)
    eng.apply([["b1", 1, "k", 0, "A", False],
               ["a2", 1, "k", 0, "B", False]])
    assert eng.read() == []          # B@0 sorts before A@0 by id
    eng.apply([["z", 1, "k", 0, "B", False]])
    assert eng.read() == [["k", ["b1", "z"]]]
    # An event may not be used twice, nor in decreasing order.
    eng = Engine(":memory:", ["seq", "B", "A"], 2)
    eng.apply([["b", 1, "k", 2, "B", False],
               ["a", 1, "k", 0, "A", False]])
    assert eng.read() == []


def check_or():
    eng = Engine(":memory:", ["or", "A", ["seq", "B", "C"]], 4)
    assert eng.apply([["a", 1, "k", 0, "A", False],
                      ["b", 1, "k", 1, "B", False],
                      ["c", 1, "k", 3, "C", False]]) == {
        "add": [["k", ["a"]], ["k", ["b", "c"]]], "remove": []}
    assert eng.read() == [["k", ["a"]], ["k", ["b", "c"]]]
    # A lone B never matches; adding C creates the sequence.

    eng = Engine(":memory:", ["or", "A", ["seq", "B", "C"]], 4)
    eng.apply([["b", 1, "k", 1, "B", False]])
    assert eng.read() == []
    eng.apply([["c", 1, "k", 3, "C", False]])
    assert eng.read() == [["k", ["b", "c"]]]


def check_plus():
    eng = Engine(":memory:", ["plus", "A"], 2)
    assert eng.apply([["a1", 1, "k", 0, "A", False]]) == {
        "add": [["k", ["a1"]]], "remove": []}
    # Overlapping plus matches collapse per id sequence.
    eng.apply([["a2", 1, "k", 2, "A", False]])
    assert eng.read() == [["k", ["a1"]], ["k", ["a1", "a2"]], ["k", ["a2"]]]
    eng.apply([["a3", 1, "k", 6, "A", False]])   # too far from a2
    assert eng.read() == [
        ["k", ["a1"]], ["k", ["a1", "a2"]], ["k", ["a2"]], ["k", ["a3"]]]
    # Non-A events may be skipped between repetitions.
    eng.apply([["x", 1, "k", 3, "X", False]])
    assert eng.read() == [
        ["k", ["a1"]], ["k", ["a1", "a2"]], ["k", ["a2"]], ["k", ["a3"]]]


def check_not():
    eng = Engine(":memory:", ["not", "X", ["seq", "A", "B"]], 4)
    eng.apply([["a", 1, "k", 0, "A", False],
               ["b", 1, "k", 4, "B", False]])
    assert eng.read() == [["k", ["a", "b"]]]
    # A blocker strictly between head and tail suppresses the match.
    eng.apply([["x", 1, "k", 2, "X", False]])
    assert eng.read() == []
    eng.apply([["x", 2, "k", 2, "X", True]])
    assert eng.read() == [["k", ["a", "b"]]]
    # Blockers outside the span do not count, the span is inclusive of its ends.
    outside = Engine(":memory:", ["not", "X", ["seq", "A", "B"]], 4)
    outside.apply([["a", 1, "k", 0, "A", False],
                   ["b", 1, "k", 4, "B", False],
                   ["x", 1, "k", 9, "X", False]])
    assert outside.read() == [["k", ["a", "b"]]]
    head = Engine(":memory:", ["not", "A", ["seq", "A", "B"]], 4)
    head.apply([["a", 1, "k", 0, "A", False],
                ["b", 1, "k", 4, "B", False]])
    assert head.read() == [["k", ["a", "b"]]]
    # A blocker at the same time as the tail but earlier in (t, id) is inside;
    # one at the tail's time but after it is outside the span.
    tie = Engine(":memory:", ["not", "X", ["seq", "A", "B"]], 4)
    tie.apply([["a", 1, "k", 0, "A", False],
               ["x", 1, "k", 4, "X", False],
               ["z", 1, "k", 4, "B", False]])
    assert tie.read() == []
    after = Engine(":memory:", ["not", "X", ["seq", "A", "B"]], 4)
    after.apply([["a", 1, "k", 0, "A", False],
                 ["b", 1, "k", 4, "B", False],
                 ["x", 1, "k", 4, "X", False]])
    assert after.read() == [["k", ["a", "b"]]]


def check_revisions():
    eng = Engine(":memory:", ["seq", "A", "B"], 2)
    eng.apply([["a", 2, "k", 0, "A", False],
               ["b", 1, "k", 2, "B", False]])
    state = dump(eng.conn)
    # Lower revision is ignored; identical replay is ignored.
    assert eng.apply([["a", 1, "k", 0, "A", False]]) == {
        "add": [], "remove": []}
    assert eng.apply([["a", 2, "k", 0, "A", False]]) == {
        "add": [], "remove": []}
    assert dump(eng.conn) == state
    # Same revision, different content conflicts and rolls back atomically.
    expect_error(eng, lambda: eng.apply([
        ["a", 2, "q", 0, "A", False],
        ["b", 1, "k", 2, "B", False]]), REVISION_CONFLICT)
    assert dump(eng.conn) == state
    assert eng.read() == [["k", ["a", "b"]]]
    # Higher revision may move the key, the time, the type, or delete.
    eng.apply([["b", 2, "other", 2, "B", False]])
    assert eng.read() == []
    eng.apply([["a", 3, "other", 0, "A", False]])
    assert eng.read() == [["other", ["a", "b"]]]
    eng.apply([["a", 4, "other", 1, "Z", False]])
    assert eng.read() == []
    eng.apply([["a", 5, "other", 1, "A", False]])
    assert eng.read() == [["other", ["a", "b"]]]
    eng.apply([["a", 6, "other", 1, "A", True]])
    assert eng.read() == []
    # A pure revision bump does not disturb matching.
    eng.apply([["b", 3, "other", 2, "B", False]])
    eng.apply([["a", 7, "other", 1, "A", False]])
    assert eng.read() == [["other", ["a", "b"]]]


def check_atomic_failure():
    import cep.engine as engine_module
    eng = Engine(":memory:", ["seq", "A", "B"], 2)
    eng.apply([["a", 1, "k", 0, "A", False],
               ["b", 1, "k", 2, "B", False]])
    image = dump(eng.conn)
    original = engine_module.derive_matches

    def explode(*_args, **_kwargs):
        raise RuntimeError("boom")

    engine_module.derive_matches = explode
    try:
        try:
            eng.apply([["c", 1, "k2", 0, "A", False],
                       ["d", 1, "k2", 1, "B", False]])
        except RuntimeError as error:
            assert str(error) == "boom"
        else:
            raise AssertionError("expected boom")
    finally:
        engine_module.derive_matches = original
    # Event rows and matches were both rolled back; the engine still works.
    assert dump(eng.conn) == image
    assert eng.read() == [["k", ["a", "b"]]]
    assert eng.apply([["c", 1, "k2", 0, "A", False],
                      ["d", 1, "k2", 1, "B", False]]) == {
        "add": [["k2", ["c", "d"]]], "remove": []}


def check_input_errors():
    expect_error(None, lambda: Engine(":memory:", ["seq", "A"], 2), PATTERN)
    expect_error(None, lambda: Engine(":memory:", ["plus"], 2), PATTERN)
    expect_error(None, lambda: Engine(":memory:", ["not", 3, "A"], 2),
                 PATTERN)
    expect_error(None, lambda: Engine(":memory:", "A", -1), INPUT)
    expect_error(None, lambda: Engine(":memory:", "A", True), INPUT)
    eng = Engine(":memory:", "A", 2)
    eng.apply([["a", 1, "k", 0, "A", False]])
    state = dump(eng.conn)
    for bad in (
        [["a", 2, "k", 1, "A", False], ["a", 3, "k", 2, "A", False]],
        [["a", True, "k", 1, "A", False]],
        [["a", 0, "k", 1, "A", False]],
        [["a", 2, "k", True, "A", False]],
        [["a", 2, "k", 1, "B", 1]],
        [["a", 2, "k", 1, "A", 0]],
        [["a", 2, 7, 1, "A", False]],
        [["a", 2, "k", 1, "A", False, "extra"]],
        [["a", 2, "k", 1, "A"]],
        [[3, 2, "k", 1, "A", False]],
        [["a", 2, "k", 1, 7, False]],
        [["a", 2, None, 1, "A", False]],
        "not a list",
        None,
    ):
        expect_error(eng, lambda bad=bad: eng.apply(bad), INPUT)
        assert dump(eng.conn) == state
    # A later invalid row rejects a batch whose earlier rows were fine.
    expect_error(eng, lambda: eng.apply([
        ["b", 1, "k", 0, "A", False],
        ["c", 1, "k", 0, "A", 1]]), INPUT)
    assert dump(eng.conn) == state


def check_persistence_and_config():
    import tempfile
    handle, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(handle)
    os.unlink(path)
    try:
        eng = Engine(path, ["seq", "A", "B"], 2)
        eng.apply([["a", 1, "k", 0, "A", False],
                   ["b", 1, "k", 2, "B", False]])
        assert eng.read() == [["k", ["a", "b"]]]
        eng.close()
        # Reopening resumes from the persisted match set.
        again = Engine(path, ["seq", "A", "B"], 2)
        assert again.read() == [["k", ["a", "b"]]]
        assert again.apply([["b", 2, "k", 2, "B", True]]) == {
            "add": [], "remove": [["k", ["a", "b"]]]}
        again.close()
        third = Engine(path, ["seq", "A", "B"], 2)
        assert third.read() == []
        third.close()
        # A different pattern or window on the same database is rejected.
        expect_error(None, lambda: Engine(path, ["or", "A", "B"], 2),
                     CONFIG_CONFLICT)
        expect_error(None, lambda: Engine(path, ["seq", "A", "B"], 3),
                     CONFIG_CONFLICT)
    finally:
        for suffix in ("", "-journal", "-wal", "-shm"):
            try:
                os.unlink(path + suffix)
            except OSError:
                pass


def check_shared_connection():
    conn = sqlite3.connect(":memory:")
    first = Engine(conn, ["seq", "A", "B"], 2)
    second = Engine(conn, ["seq", "A", "B"], 2)
    first.apply([["a", 1, "k", 0, "A", False]])
    second.apply([["b", 1, "k", 2, "B", False]])
    assert first.read() == [["k", ["a", "b"]]]
    second.close()          # borrowed connections are not closed
    assert tuple(conn.execute("SELECT 1").fetchone()) == (1,)
    first.close()
    conn.close()


def check_idempotent_replay():
    for pattern in PATTERNS:
        for window in (0, 2):
            eng = Engine(":memory:", pattern, window)
            model = Model(pattern, window)
            rng = random.Random(2026)
            rows = [["e%d" % i, 1, rng.choice(("k1", "k2", "k3")),
                     rng.randrange(-2, 9), rng.choice("ABCX"),
                     rng.random() < 0.3] for i in range(12)]
            before = model.read()
            after = model.apply(rows)
            assert eng.apply(rows) == delta(before, after)
            assert eng.read() == sorted(after,
                                        key=lambda entry: (entry[0],
                                                           entry[1]))
            # Re-applying the same batch is a no-op everywhere.
            assert eng.apply(rows) == {"add": [], "remove": []}


def check_read_and_delta_shape():
    eng = Engine(":memory:", ["or", "A", "B"], 3)
    eng.apply([["b2", 1, "k2", 0, "B", False],
               ["a1", 1, "k1", 1, "A", False]])
    assert eng.read() == [["k1", ["a1"]], ["k2", ["b2"]]]
    change = eng.apply([["b2", 2, "k2", 0, "B", True],
                        ["a2", 1, "k2", 2, "A", False]])
    assert change == {"add": [["k2", ["a2"]]], "remove": [["k2", ["b2"]]]}
    assert eng.read() == [["k1", ["a1"]], ["k2", ["a2"]]]
    assert eng.apply([]) == {"add": [], "remove": []}


# ---------------------------------------------------------------------------
# differential fuzzing against the independent oracle
# ---------------------------------------------------------------------------

PATTERNS = [
    "A",
    ["seq", "A", "B"],
    ["seq", ["plus", "A"], "B"],
    ["or", "A", ["seq", "B", "C"]],
    ["not", "X", ["seq", "A", "B"]],
    ["not", "X", ["plus", "A"]],
    ["seq", ["not", "B", "A"], "B"],
    ["seq", ["or", "A", "B"], ["plus", "C"]],
    ["plus", ["seq", "A", "B"]],
    ["seq", "A", ["not", "C", ["seq", "B", "A"]]],
]


def fuzz(pattern, window, seed, batches, keys=("k1", "k2", "k3")):
    eng = Engine(":memory:", pattern, window)
    model = Model(pattern, window)
    rng = random.Random(seed)
    ids = ["e%02d" % i for i in range(18)]
    known = {}
    for _ in range(batches):
        rows = []
        used = set()
        for _ in range(rng.randrange(7)):
            rid = rng.choice(ids)
            if rid in used:
                continue
            used.add(rid)
            previous = known.get(rid)
            roll = rng.random()
            if previous is not None and roll < 0.18:
                rev, key, t, kind, deleted = previous
                rows.append([rid, rev, key, t, kind, deleted])   # replay
                continue
            if previous is not None and roll < 0.30 and previous[0] > 1:
                rev = rng.randrange(1, previous[0])
                rows.append([rid, rev, rng.choice(keys), rng.randrange(-2, 9),
                             rng.choice("ABCX"), rng.random() < 0.3])
                continue
            rev = 1 if previous is None else previous[0] + 1
            mutated = [rev, rng.choice(keys), rng.randrange(-2, 9),
                       rng.choice("ABCX"), rng.random() < 0.3]
            rows.append([rid] + mutated)
            known[rid] = tuple(mutated)
        before = model.read()
        after = model.apply(rows)
        change = eng.apply(rows)
        assert change == delta(before, after), (pattern, window, rows,
                                                change, delta(before, after))
        assert eng.read() == sorted(after, key=lambda entry: (entry[0],
                                                              entry[1])), \
            (pattern, window, rows, eng.read(), after)
    # A conflicting revision rejects the whole batch and changes nothing.
    rid = min(known)
    rev, key, t, kind, deleted = known[rid]
    before_read = eng.read()
    variants = [
        [rid, rev, key + "!", t, kind, deleted],
        [rid, rev, key, t + 7, kind, deleted],
        [rid, rev, key, t, "Z" if kind != "Z" else "Y", deleted],
        [rid, rev, key, t, kind, not deleted],
    ]
    for clash in variants:
        expect_error(eng, lambda clash=clash: eng.apply([clash]),
                     REVISION_CONFLICT)
        assert eng.read() == before_read


def check_fuzz():
    for index, pattern in enumerate(PATTERNS):
        fuzz(pattern, index % 5, seed=7100 + index, batches=120)


# ---------------------------------------------------------------------------
# locality and blocking propagation
# ---------------------------------------------------------------------------

def check_locality():
    eng = Engine(":memory:", ["seq", "A", "B"], 3)
    # One key with matches far apart in time plus many distant events.
    rows = [["a0", 1, "far", 0, "A", False],
            ["b0", 1, "far", 1, "B", False]]
    for step in range(2, 10):
        rows.append(["a%d" % step, 1, "far", step * 100, "A", False])
        rows.append(["b%d" % step, 1, "far", step * 100 + 1, "B", False])
    rows.append(["a10", 1, "far", 1000, "A", False])
    rows.append(["b10", 1, "far", 1001, "B", False])
    rows.append(["near", 1, "near", 0, "A", False])
    rows.append(["nearb", 1, "near", 1, "B", False])
    eng.apply(rows)
    assert eng.read() == [
        ["far", ["a0", "b0"]], ["far", ["a10", "b10"]],
        ["far", ["a2", "b2"]], ["far", ["a3", "b3"]],
        ["far", ["a4", "b4"]], ["far", ["a5", "b5"]],
        ["far", ["a6", "b6"]], ["far", ["a7", "b7"]],
        ["far", ["a8", "b8"]], ["far", ["a9", "b9"]],
        ["near", ["near", "nearb"]],
    ]
    before_near = [entry for entry in eng.read() if entry[0] == "near"]
    before_far_remote = [entry for entry in eng.read()
                         if entry[0] == "far" and entry[1] == ["a0", "b0"]]
    # Touch only the tail of the far key: only that neighbourhood is examined.
    change = eng.apply([["b10", 2, "far", 1001, "B", True]])
    assert change == {"add": [], "remove": [["far", ["a10", "b10"]]]}
    assert eng.stats["keys_visited"] == 1, eng.stats
    assert eng.stats["events_scanned"] <= 4, eng.stats
    assert eng.stats["matches_rebuilt"] <= 2, eng.stats
    assert [entry for entry in eng.read() if entry[0] == "near"] == before_near
    assert [entry for entry in eng.read()
            if entry[0] == "far" and entry[1] == ["a0", "b0"]] == \
        before_far_remote
    # Unrelated keys are not visited at all.
    near_only = eng.apply([["nearb", 2, "near", 1, "B", False]])
    assert near_only == {"add": [], "remove": []}
    assert eng.stats["keys_visited"] == 0, eng.stats


def check_blocking_propagation():
    eng = Engine(":memory:", ["not", "X", ["seq", "A", "B"]], 10)
    eng.apply([["a", 1, "k", 0, "A", False],
               ["b", 1, "k", 10, "B", False],
               ["a2", 1, "k", 100, "A", False],
               ["b2", 1, "k", 110, "B", False]])
    assert eng.read() == [["k", ["a", "b"]], ["k", ["a2", "b2"]]]
    # A blocker inside the first span removes exactly that match.
    change = eng.apply([["x", 1, "k", 5, "X", False]])
    assert change == {"add": [], "remove": [["k", ["a", "b"]]]}
    assert eng.read() == [["k", ["a2", "b2"]]]
    assert eng.stats["keys_visited"] == 1, eng.stats
    assert eng.stats["events_scanned"] <= 4, eng.stats
    # Removing the blocker restores it; the distant match never moved.
    change = eng.apply([["x", 2, "k", 5, "X", True]])
    assert change == {"add": [["k", ["a", "b"]]], "remove": []}
    assert eng.read() == [["k", ["a", "b"]], ["k", ["a2", "b2"]]]
    # A far away blocker outside any span changes nothing and scans little.
    change = eng.apply([["x3", 1, "k", 60, "X", False]])
    assert change == {"add": [], "remove": []}
    assert eng.stats["events_scanned"] <= 3, eng.stats


def check_two_connections():
    conn = sqlite3.connect(":memory:")
    left = Engine(conn, ["seq", "A", "B"], 2)
    right = Engine(conn, ["seq", "A", "B"], 2)
    left.apply([["a", 1, "k", 0, "A", False]])
    right.apply([["b", 1, "k", 2, "B", False]])
    assert left.read() == right.read() == [["k", ["a", "b"]]]
    right.apply([["b", 2, "k", 2, "B", True]])
    assert left.read() == []
    left.close()
    right.close()
    conn.close()


def normal():
    check_big_numbers()
    check_spec_example()
    check_skipping_and_order()
    check_or()
    check_plus()
    check_not()
    check_revisions()
    check_input_errors()
    check_atomic_failure()
    check_persistence_and_config()
    check_shared_connection()
    check_read_and_delta_shape()
    check_idempotent_replay()
    check_locality()
    check_blocking_propagation()
    check_two_connections()
    print("NORMAL_REGRESSION_OK")


def verify():
    normal()
    check_fuzz()
    print("DIFFERENTIAL_OK")
    return 0


def demo():
    print("=" * 70)
    print("设备采集故障链：按事件修订增量维护复合事件匹配")
    print("=" * 70)
    eng = Engine(":memory:", ["seq", ["plus", "ALARM"], "OFFLINE"], 10)
    steps = [
        ("采集器上报三条告警与一次离线", [
            ["alarm-1", 1, "dev-7", 0, "ALARM", False],
            ["alarm-2", 1, "dev-7", 3, "ALARM", False],
            ["alarm-3", 1, "dev-7", 6, "ALARM", False],
            ["offline-1", 1, "dev-7", 9, "OFFLINE", False],
        ]),
        ("历史更正：离线事件系误报，撤销", [
            ["offline-1", 2, "dev-7", 9, "OFFLINE", True],
        ]),
        ("复核后恢复离线事件", [
            ["offline-1", 3, "dev-7", 9, "OFFLINE", False],
        ]),
        ("相邻设备出现同类故障链（键间隔离）", [
            ["alarm-9", 1, "dev-8", 1, "ALARM", False],
            ["offline-8", 1, "dev-8", 8, "OFFLINE", False],
            ["noise", 1, "dev-8", 4, "ALARM", False],
        ]),
    ]
    for label, rows in steps:
        change = eng.apply(rows)
        print("\n[%s]" % label)
        print("  净变化:", canon(change))
        print("  当前匹配:", canon(eng.read()))
    print("\n完成：撤销离线事件即移除了整条故障链，恢复后重新出现。")
    return 0


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) == 2 else "verify"
    if mode == "normal":
        normal()
    elif mode == "verify":
        sys.exit(verify())
    elif mode == "demo":
        sys.exit(demo())
    else:
        raise SystemExit("usage: python3 checks.py normal|verify|demo")
