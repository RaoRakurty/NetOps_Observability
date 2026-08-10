# netops-vector-router — the pinned stock Vector image + a static curl.
#
# WHY (F-7, TLS assurance run 2026-08-09): the router's Sealed Fields secret
# backend (cx-secret-backend.sh, wired in vector.yaml `secret:`) executes curl
# to fetch per-tenant edge keys from the api — over mutual TLS presenting the
# router's own workload certificate. The stock alpine image ships only BusyBox
# wget, which has NO client-certificate options, so the fetch could never run
# in ANY transport mode: with a seal rule present, Vector refused its config at
# every load. Fail-closed, but the feature was undeliverable in-image.
#
# Only the ROUTER gets this image: the aggregator never runs the secret
# backend and stays on the stock pin (same digest as the FROM below).
#
# APK_REPO_SCHEME exists for hosts whose egress intercepts TLS (the lab): apk
# verifies SIGNED package indexes either way, so http loses nothing that the
# signature does not still guarantee. The tracked default stays https.
#   docker compose build vector-router                    # normal hosts / CI
#   docker build --build-arg APK_REPO_SCHEME=http ...     # TLS-intercepted egress
FROM timberio/vector:0.40.0-alpine@sha256:7a81fdd62e056321055a9e4bdec4073d752ecf68f4c192e676b85001721523c2

ARG APK_REPO_SCHEME=https
RUN sed -i "s|^https://|${APK_REPO_SCHEME}://|" /etc/apk/repositories \
	&& apk add --no-cache curl \
	&& sed -i "s|^http://|https://|" /etc/apk/repositories
