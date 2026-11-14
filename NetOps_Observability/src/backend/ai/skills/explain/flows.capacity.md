---
topic: flows.capacity
question: How is link capacity worked out on the Flows page?
keywords: link capacity, 95th percentile, peak utilisation, headroom, days to 90, forecast, no reported speed
---
Capacity reads the interface counters of every link that reports a speed, not
the flow records. For the window you chose it shows the 95th percentile and the
peak of the five-minute traffic rate in the busier direction, in percent of the
link speed, and the headroom left. "Reaches 90%" fits a straight line through
each complete day's 95th percentile over the last 28 days; it needs 14 days of
history and a steady trend, otherwise no date is shown. A link whose router
reports no usable interface speed, or a speed lower than the traffic it
carries, is listed under "Speed not reported": it has its throughput but no
percentage, headroom or forecast.
