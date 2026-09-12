---
topic: wifi.inventory-empty
question: How do I fill the wireless inventory?
keywords: no wireless inventory, wireless connector, catalyst 9800, wireless empty
---
The wireless view is written by a vendor controller connector, not by
discovery. Add the controller integration under NMS integrations with
read-only credentials, and the controllers, access points, radios and WLAN
profiles it publishes appear here as they are read. Access-point join and radio
state also start arriving as evidence for correlation. Until a connector is
added there is nothing to show, which is not a claim that you have no wireless.
