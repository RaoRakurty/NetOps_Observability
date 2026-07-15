FROM python:3.12-slim
# google-auth: the GCP service-account OAuth flow needs RS256 signing that the
# stdlib cannot do — same dependency posture as boto3 (this is the lab poller
# container, not the stdlib-only Go backend).
RUN pip install --no-cache-dir boto3 kafka-python-ng==2.2.3 google-auth requests
# Copy ALL poller modules (not an explicit list) — a per-file COPY silently
# dropped new modules twice (trail_state, cloud_events), crash-looping the
# container on import. test_*.py ride along harmlessly (never executed here).
COPY *.py /
# Non-root by design (SC-008 / Trivy DS-0002). This lab poller reads AWS creds
# from a mounted ~/.aws (mode 600, owned by the lab operator uid/gid 1000) and
# writes the live inventory + flow logs into host bind-mounts owned by that same
# 1000:1000. Running as 1000:1000 reads/writes all of them with NO root — the
# creds mount is remapped to this user's home (see the compose override).
RUN groupadd -g 1000 poller && useradd -u 1000 -g 1000 -m -d /home/poller poller
ENV HOME=/home/poller
USER poller
CMD ["python", "-u", "/poller.py"]
