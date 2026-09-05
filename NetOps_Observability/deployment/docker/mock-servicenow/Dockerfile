# Multi-stage build for the mock-servicenow test fixture (#78).
#
# A tiny, stdlib-only ServiceNow Table API stub used to exercise Correlix's RCA
# auto-ticketing create leg end-to-end without a real ServiceNow instance. Off by
# default — started only via the "mock-snow" compose profile.
#
# Pinned to the same patched Go toolchain + distroless runtime as the API image.
FROM golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS build
WORKDIR /src
COPY deployment/docker/mock-servicenow/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mock-servicenow .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

# The image's licence, in OCI metadata, so `docker image inspect` answers it
# without unpacking the image. Correlix core is Apache-2.0; see LICENSING.md for
# which parts of the tree are commercial add-ons instead. Enforced by
# scripts/licensing-gate.py check D and tests/test_licensing_consistency.py.
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/mock-servicenow /mock-servicenow
USER nonroot:nonroot
EXPOSE 8090
ENTRYPOINT ["/mock-servicenow"]
