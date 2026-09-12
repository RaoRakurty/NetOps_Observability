---
topic: lane.not-enabled
question: What if the security lane is off?
keywords: lane not enabled, feature_security_lane, lane disabled
---
The lane is switched on with FEATURE_SECURITY_LANE. While it is off the routes
are not registered at all, so nothing assesses this estate on a schedule and no
scan can be started from the console. That is a deployment fact, not an idle
lane and not an empty result. Anything the Security pages show while the lane
is off was produced by other sources, such as imported findings or the flow and
log pipelines.
