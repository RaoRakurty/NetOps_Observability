# Time, Diff, and Golden Path

## Rule

Topology is time-aware.

Every node and edge should support:
- first_seen
- last_seen
- valid_from
- valid_to
- change_state
- current_state
- previous_state
- golden_state

## Change states

- added
- removed
- changed
- unchanged
- stale
- unknown

## Required workflows

Future Change Review:
- live vs previous
- live vs golden
- live vs historical

Future Path Trace:
- current path
- golden path
- historical path
- path divergence
