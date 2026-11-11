# Multi-stage build for the mock-nms test fixture (#95).
#
# A tiny, stdlib-only Cisco Catalyst SD-WAN Manager (vManage) API stub used to
# exercise Correlix's NMS vendor-controller integration cycle end-to-end without
# a real controller. Off by default — started only via the "mock-nms" compose
# profile.
#
# Pinned to the same patched Go toolchain + distroless runtime as the API image.
FROM golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build
WORKDIR /src
COPY deployment/docker/mock-nms/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mock-nms .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

# The image's licence, in OCI metadata, so `docker image inspect` answers it
# without unpacking the image. Correlix core is Apache-2.0; see LICENSING.md for
# which parts of the tree are commercial add-ons instead. Enforced by
# scripts/licensing-gate.py check D and tests/test_licensing_consistency.py.
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/mock-nms /mock-nms
USER nonroot:nonroot
EXPOSE 8091
ENTRYPOINT ["/mock-nms"]
