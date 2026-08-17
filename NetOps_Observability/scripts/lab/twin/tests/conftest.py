"""Test wiring for the twin package: the flat modules live one directory up
(the same sys.path the `twin.py` entrypoint uses)."""
import os
import sys

TWIN_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if TWIN_DIR not in sys.path:
    sys.path.insert(0, TWIN_DIR)

# repo root (NetOps_Observability/) for locating the shipped example scenario
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(TWIN_DIR)))
