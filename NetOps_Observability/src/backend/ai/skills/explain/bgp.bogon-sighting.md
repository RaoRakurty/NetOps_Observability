---
topic: bgp.bogon-sighting
question: What does a bogon sighting mean?
keywords: bogon, reserved address space, leak, misconfigured neighbour, seen on your network
---
A bogon is address space that must never appear in the global routing table:
reserved, private or undelegated blocks. Anything listed under "Seen on your
network" was observed on your OWN routers' BMP feed or in your update ring, so
it is either a leak into your network or a misconfigured neighbour. It is never
normal traffic. Filter it at your edge and ask the neighbour announcing it to
stop. Nothing here comes from someone else's network.
