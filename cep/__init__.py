"""Pointwise complex-event matching engine (standard library + SQLite only).

Public entry point::

    from cep import Engine
    eng = Engine(db, pattern, W)      # db: SQLite path or ":memory:"
    eng.apply(rows)                   # rows: [[id, rev, key, t, type, deleted], ...]
    eng.read()                        # [ [key, [id, ...]], ... ]

The engine keeps the highest revision per event id and continuously matches
live events of one key, in (t, id) order, against a fixed pattern.  Only the
part of one key's match set that a batch can actually affect is examined;
nothing is ever recomputed for untouched keys and untouched windows.
"""

from .engine import (
    Engine,
    INPUT,
    PATTERN,
    REVISION_CONFLICT,
    CONFIG_CONFLICT,
)

__all__ = [
    "Engine",
    "INPUT",
    "PATTERN",
    "REVISION_CONFLICT",
    "CONFIG_CONFLICT",
]
