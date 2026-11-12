# Pointwise complex-event engine

An incremental device-fault-chain matcher: Python standard library plus SQLite,
no third-party dependency.

## Public entry points

```python
from cep import Engine

eng = Engine(db, pattern, W)        # db: SQLite path, ":memory:", or a connection
eng.apply(rows)                     # [[id, rev, key, t, type, deleted], ...]
eng.read()                          # [[key, [id, ...]], ...]
eng.close()
```

`apply` returns `{"add": [...], "remove": [...]}`, both arrays in the same
`[key, [id, ...]]` shape as `read`, listing only the net change against the
previous batch.  `read` returns every current match, ordered by key and then
by id sequence.

Errors raise `ValueError` with a short code: `INVALID` for malformed batches,
`REVISION_CONFLICT` for equal revisions with different content, `PATTERN`
for malformed patterns, `CONFIG_CONFLICT` when an existing database is opened
with a different pattern or window.  The CLI prints `{"error": CODE}` and
exits 2 for the same conditions.

## Pattern language

A pattern is a type name, or a nested array using `["seq", p, q]`,
`["or", p, q]`, `["plus", p]`, `["not", type, p]`.

* `seq(p, q)`: a `p` match followed by a `q` match; later events only.
* `or(p, q)`: a `p` match or a `q` match.
* `plus(p)`: one or more successive `p` matches.
* `not(T, p)`: a `p` match whose span contains no live event of type `T`.

A match's *span* runs from its first to its last matched event in the key's
`(t, id)` order; the head-to-tail time difference must be at most `W`.  Live
events of each key are matched in strictly increasing `(t, id)` order, and
events may be skipped.  For `not`, an event of the named type is inside the
span only when it lies strictly between the head and the tail, so a match's
own endpoints never exclude it.  Matches are identified by their ordered id
sequence: equivalent derivations of one sequence are stored once, and every
distinct sequence is a distinct match.

## Revision and persistence semantics

`rows` items are `[id, rev, key, t, type, deleted]`, `id`/`key`/`type` strings,
`rev` a positive integer, `t` an integer of any size, `deleted` a bool.  Ids
are unique within a batch and `W` is a non-negative integer.  Per id only the
highest revision is kept, tombstones included.  Lower revisions are ignored;
an equal revision with equal content is a no-op; an equal revision with
different content rejects the whole batch with `REVISION_CONFLICT`.  A higher
revision may change key, time, type, delete, or revive.

Highest revisions live in `cep_events`, the match set in `cep_matches`, both
in the same SQLite database.  One `apply` writes events and matches inside a
single transaction, so a rejected batch leaves both untouched and a reopen
resumes from the persisted match set.  Event times are stored through an
order-preserving textual encoding, because SQLite's integer range is narrower
than Python's.

## Incrementality

An `apply` visits only the keys whose live state some accepted revision
changed, and for each such key only the neighbourhood of the changed
positions:

* Any match that can change has a span meeting a changed position, and such a
  match has its head at most `W` before the change.  Matches whose spans miss
  the changed positions are reused verbatim, never recomputed.
* Events are fetched with bounded `key`/`t` range queries covering
  `changed ± W`; distant history is never read.
* Changed positions farther apart than `W` cannot share a match and are
  processed as separate clusters.  A single changed event can also break or
  create a `not` exclusion for a match whose span surrounds it, so the
  surrounding span is rebuilt as well; all stale rows of a key are collected
  before any are rewritten, because one id sequence can migrate from one
  change's neighbourhood to another's.

`Engine.stats` records the work of the last `apply` (`keys_visited`,
`events_scanned`, `matches_rebuilt`), and the verification suite asserts that
touching one key's tail scans a bounded number of events and visits no other
key.

## Running it

```
python3 cep/cli.py setup         # runtime info plus a loadable self-check
python3 cep/cli.py verify        # business regressions + differential fuzzing
python3 cep/cli.py demo          # fault-chain walkthrough
python3 cep/cli.py apply --db FILE --pattern '["seq","ALARM","OFFLINE"]' --window 2 BATCH.json
python3 cep/cli.py read  --db FILE --pattern '["seq","ALARM","OFFLINE"]' --window 2
```

`checks.py` holds the same verification entry points (`normal`, `verify`,
`demo`).  Expected results are produced by `cep/oracle.py`, an independent
full recomputation of every key, never by the engine itself.

## Layout

| File | Purpose |
| --- | --- |
| `cep/engine.py` | revision store, pattern derivation, incremental maintenance |
| `cep/oracle.py` | independent full-recompute oracle |
| `cep/cli.py` | CLI and runtime-manifest entry points |
| `samples/window.json`, `samples/correction.json` | CLI example batches |
| `checks.py` | business regressions, differential fuzzing, demo |
| `.pointwise-runtime.json` | `version=1`, `kind=cli`, argv lists |
