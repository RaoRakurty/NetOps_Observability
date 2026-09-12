---
topic: bgp.geofeed-publish
question: How does a holder publish a geofeed?
keywords: geofeed, rfc 8805, rfc 9092, inetnum, geofeed attribute, publish locations
---
A holder advertises a geofeed by putting a geofeed: attribute — or a
"Geofeed <url>" remark — on their inet(6)num registry object, and serving a
CSV of prefix, country, region, city and postal code at that URL. This page
discovers the URL from the registry object and reads it. When nothing is
published, that is a fact and not an error: it means the holder has said
nothing, so any claim about where the space is used is a third-party guess.
