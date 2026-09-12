---
topic: bgp.visibility
question: What does "Reaching the internet" measure?
keywords: visibility, collectors seeing it, ris peers, reaching the internet, announced
---
It is the share of public route collectors that currently see the selected
prefix or AS. The platform asks RIPE NCC's Routing Information Service how many
of its full-feed peers hold a route for the resource and divides by the total.
Above ninety per cent is normal. A fall means part of the internet has stopped
learning your prefix — usually a dropped or filtered session to an upstream.
A dash means the measurement was not taken for this resource; it is not a zero
and not a pass.
