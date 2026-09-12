# Twin lab-tool image (tracker 152 fidelity wave, design §4.1).
#
# One image serves both roles of the compose overlay's `twin` service:
#   * snmpsim agent supervisor (PID 1: snmpsim_supervisor.py — one pinned
#     snmpsim-command-responder per simulated device on its twinnet address),
#   * UDP emitter agent (docker exec → udp_agent.py, per-device source binds
#     for traps/NetFlow in `--fidelity source_ip` mode).
#
# The twin CODE is bind-mounted read-only at /twin by the overlay (the flowgen
# precedent) — this image carries only the pinned dependencies + iproute2.
# Digest-pinned base like every image in deployment/docker/docker-compose.yml.
FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a

# iproute2: the alias management (`ip addr add`) both roles need.
# `twin` user: snmpsim-command-responder REFUSES to keep running as root; it
# binds :161 first (needs root in this netns) then drops to --process-user.
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin twin

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

ENV PYTHONUNBUFFERED=1
# Default command is the agent supervisor; the overlay passes the manifest
# path explicitly (kept here as documentation of the contract).
CMD ["python3", "/twin/snmpsim_supervisor.py", "--manifest", "/data/twin/agents/manifest.json"]
