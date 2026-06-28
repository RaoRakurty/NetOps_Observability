# Multi-stage build for the mock-servicenow test fixture (#78).
#
# A tiny, stdlib-only ServiceNow Table API stub used to exercise Correlix's RCA
# auto-ticketing create leg end-to-end without a real ServiceNow instance. Off by
# default — started only via the "mock-snow" compose profile.
#
# Pinned to the same patched Go toolchain + distroless runtime as the API image.
FROM golang:1.25.11-alpine@sha256:c05ba4b73604069d376c4f41346b05374335b5ca0c46fb6dfede5a59f5196931 AS build
WORKDIR /src
COPY deployment/docker/mock-servicenow/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mock-servicenow .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
COPY --from=build /out/mock-servicenow /mock-servicenow
USER nonroot:nonroot
EXPOSE 8090
ENTRYPOINT ["/mock-servicenow"]
