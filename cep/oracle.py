"""Independent full-recomputation oracle for the pointwise CEP engine.

Deliberately recomputes every key from the persisted source rows; it shares no
matching code with ``cep.engine``.  Used by the verification suite to compare
incremental results against ground truth after every batch.
"""

def match_ids(pattern, events, window):
    """Return the set of matches (as id-sequence tuples) of ``pattern``.

    ``events`` is an ordered list of ``(id, t, type)``, ordered by (t, id).
    """
    times = [event[1] for event in events]

    def fits(match):
        return times[match[-1]] - times[match[0]] <= window

    def derive(node):
        if isinstance(node, str):
            return frozenset((i,) for i, event in enumerate(events)
                             if event[2] == node)
        kind = node[0]
        if kind == "seq":
            left = derive(node[1])
            right = derive(node[2])
            out = set()
            for head in left:
                for tail in right:
                    if tail[0] > head[-1] and \
                            times[tail[-1]] - times[head[0]] <= window:
                        out.add(head + tail)
            return frozenset(out)
        if kind == "or":
            return frozenset(derive(node[1]) | derive(node[2]))
        if kind == "plus":
            base = {match for match in derive(node[1]) if fits(match)}
            out = set(base)
            frontier = set(base)
            while frontier:
                next_frontier = set()
                for left in frontier:
                    for right in base:
                        joined = left + right
                        if right[0] > left[-1] and \
                                times[joined[-1]] - times[joined[0]] <= window:
                            if joined not in out:
                                next_frontier.add(joined)
                                out.add(joined)
                frontier = next_frontier
            return frozenset(out)
        if kind == "not":
            inner = derive(node[2])
            name = node[1]
            excluded = {i for i, event in enumerate(events)
                        if event[2] == name}
            out = set()
            for match in inner:
                if not fits(match):
                    continue
                span = set(range(match[0] + 1, match[-1]))
                if not (span & excluded):
                    out.add(match)
            return frozenset(out)
        raise AssertionError("bad pattern")

    return {tuple(events[i][0] for i in match) for match in derive(pattern)}


def oracle(records, pattern, window):
    """Full recomputation of the match set over all persisted records.

    ``records`` maps id -> (rev, key, t, type, deleted).
    """
    live = {}
    for rid, (rev, key, t, kind, deleted) in records.items():
        if deleted:
            continue
        live.setdefault(key, []).append((rid, t, kind))
    result = []
    for key in sorted(live):
        events = sorted(live[key], key=lambda event: (event[1], event[0]))
        for ids in sorted(match_ids(pattern, events, window)):
            result.append([key, list(ids)])
    return result


def normalise_read(value):
    return [[key, list(ids)] for key, ids in value]
