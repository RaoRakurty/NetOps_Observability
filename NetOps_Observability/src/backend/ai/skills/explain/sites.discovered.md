---
topic: sites.discovered
question: What is a discovered site, and what does adopting it do?
keywords: discovered site, adopt discovered sites, site id, vmanage site, controller site, reported site, branch grouping
---
A discovered site comes from the site id a controller (for example vManage)
or the device itself reports, for a device no operator has placed. The
topology already groups those devices by it and marks the group as
discovered; nothing is saved as a site. Adopting turns the ticked ones into
real sites, named "Site 50" or the controller's own site name, and places
their devices on them, so you can rename them and give them coordinates.
A device already placed by an operator or by its site label is never moved,
and adopting twice changes nothing.
