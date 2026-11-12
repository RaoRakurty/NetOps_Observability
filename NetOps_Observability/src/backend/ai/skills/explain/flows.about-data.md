---
topic: flows.about-data
question: Where does the Flows page get its numbers?
keywords: traffic data sources, flow sources, sampling rate, flow coverage
---
Volumes come from the NetFlow, IPFIX and sFlow records your devices export.
When a device reports its sampling rate, its counts are scaled by that rate;
when it reports none, they are shown as received, which reads low if the device
samples without saying so. Nothing is estimated beyond that. Utilisation and
capacity come from the interface counters collected over SNMP. Correlix's own
polling traffic is left out unless you choose to show it. Countries and
networks appear only once their datasets are loaded.
