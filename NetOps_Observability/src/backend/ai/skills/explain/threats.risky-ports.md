---
topic: threats.risky-ports
question: Which ports count as high risk?
keywords: high-risk ports, risky service exposure, telnet ftp smb rdp
---
The high-risk list is legacy management and remote-access services that are
common lateral-movement paths: FTP, Telnet, MS-RPC, NetBIOS, SMB, MSSQL, RDP,
VNC, MySQL, Redis, memcached, NFS and the r-services. Traffic to them is
counted in bytes from flow records. Seeing none in this window means no flow
recorded any — not that the services are closed. Confirm with the exposure
findings for the device before concluding anything.
