####
# NetBox extra configuration (mounted at /etc/netbox/config/extra.py).
#
# netbox-docker's stock configuration.py does NOT map BASE_PATH from an env var,
# so we wire it here: when BASE_PATH is set, NetBox serves under that subpath
# (e.g. /netbox/), which is what lets the platform's nginx expose its UI at
# /netbox/ behind the single :8000 entry point. NetBox normalizes the value
# (adds a trailing slash). Empty/unset → served at root (unchanged).
####
import os

BASE_PATH = os.environ.get("BASE_PATH", "")
