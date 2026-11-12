"""Command line entry point for the pointwise CEP engine.

Subcommands
-----------
setup   Print runtime information and a loadable self-check.
verify  Run the business regressions plus differential fuzzing.
demo    Walk a device acquisition fault-chain scenario.
apply   Apply a batch to a database and print the net match change.
read    Print all current matches of a database.

``apply`` and ``read`` accept ``--pattern`` (JSON, or a bare type name) and
``--window``; they print exactly one JSON value.  Failures print
``{"error": CODE}`` and exit 2.
"""

import argparse
import json
import os
import platform
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from cep import Engine, CONFIG_CONFLICT, INPUT, PATTERN, REVISION_CONFLICT


def _load_pattern(text):
    try:
        return json.loads(text)
    except ValueError:
        return text


def _connect_engine(args):
    pattern = _load_pattern(args.pattern)
    engine = Engine(args.db, pattern, args.window)
    return engine


def _error_code(error):
    message = str(error)
    for code in (INPUT, PATTERN, REVISION_CONFLICT, CONFIG_CONFLICT):
        if message == code:
            return code
    return INPUT


def cmd_setup(_args):
    info = {
        "package": "cep",
        "version": 1,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "standard_library_only": True,
        "entry_points": ["setup", "verify", "demo", "apply", "read"],
    }
    # Loadable self-check: an empty database must construct and read.
    eng = Engine(":memory:", "A", 0)
    assert eng.read() == []
    eng.close()
    print(json.dumps(info, ensure_ascii=False, indent=2))
    return 0


def cmd_verify(_args):
    import checks
    return checks.verify()


def cmd_demo(_args):
    import checks
    return checks.demo()


def cmd_apply(args):
    try:
        with open(args.batch, "r", encoding="utf-8") as handle:
            rows = json.load(handle, parse_constant=_reject_constant)
        if isinstance(rows, dict):
            rows = rows["rows"]
        eng = _connect_engine(args)
        change = eng.apply(rows)
        eng.close()
        print(json.dumps(change, ensure_ascii=False, sort_keys=True))
        return 0
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(json.dumps({"error": _error_code(error)}))
        return 2


def cmd_read(args):
    try:
        eng = _connect_engine(args)
        result = eng.read()
        eng.close()
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(json.dumps({"error": _error_code(error)}))
        return 2


def _reject_constant(_value):
    raise ValueError(INPUT)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cep")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("setup", help="print runtime info and self-check")
    sub.add_parser("verify", help="run business regressions and fuzzing")
    sub.add_parser("demo", help="walk a fault-chain scenario")

    apply_parser = sub.add_parser("apply", help="apply a batch")
    apply_parser.add_argument("--db", required=True)
    apply_parser.add_argument("--pattern", required=True)
    apply_parser.add_argument("--window", required=True, type=int)
    apply_parser.add_argument("batch")
    apply_parser.set_defaults(func=cmd_apply)

    read_parser = sub.add_parser("read", help="print current matches")
    read_parser.add_argument("--db", required=True)
    read_parser.add_argument("--pattern", required=True)
    read_parser.add_argument("--window", required=True, type=int)
    read_parser.set_defaults(func=cmd_read)

    args = parser.parse_args(argv)
    if args.command == "setup":
        return cmd_setup(args)
    if args.command == "verify":
        return cmd_verify(args)
    if args.command == "demo":
        return cmd_demo(args)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
