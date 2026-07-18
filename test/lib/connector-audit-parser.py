#!/usr/bin/env python3
"""Runnable entrypoint for the shared connector e2e audit parser.

It is the security boundary of every connector e2e suite: its exit code is the phase
status. 0 hold, 1 retryable miss, 4 security breach (fatal, never retried), 2 usage.
The shell classifier supplies 2 (timeout) and 3 (budget).

The crash guard is deliberately SPLIT so that main()'s own intended exit codes
(0/1/4, raised as SystemExit by sys.exit/die/insecure) are preserved, while an
import-time failure - including an import-time SystemExit (a spec module or argparse
exiting during import) - maps to 4. Re-raising every SystemExit would let an
import-time SystemExit(1) stay a retryable 1, which the shell normalizer would launder
via the per-attempt audit truncation.
"""
import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from connector_audit.engine import main
except BaseException as e:  # noqa: BLE001 - ANY import-time failure (incl. SystemExit) is fatal.
    print("SECURITY: parser import failed (%s: %s) - failing closed" % (type(e).__name__, e))
    sys.exit(4)
if __name__ == "__main__":
    try:
        main(sys.argv)
    except SystemExit:
        raise  # main's own intended 0/1/4.
    except BaseException as e:  # noqa: BLE001 - any runtime crash is fatal, never retried.
        print("SECURITY: parser crash (%s: %s) - failing closed" % (type(e).__name__, e))
        sys.exit(4)
