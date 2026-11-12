---
topic: flows.capacity
question: How is link capacity worked out on the Flows page?
keywords: link capacity, peak utilisation, average utilisation, headroom
---
Capacity reads the interface counters of every link that reports a speed. For
the window you chose it shows the average and the peak of the five-minute
traffic rate, in percent of the link speed, for the busier direction and for
each direction on its own. Links are sorted by their peak, so the links closest
to full come first. Links without a reported speed have no utilisation and are
not listed. The 95th percentile, the headroom left and the days until a link
reaches 90 per cent are not computed yet.
