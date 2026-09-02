# Multi-stage build for the mock-nms test fixture (#95).
#
# A tiny, stdlib-only Cisco Catalyst SD-WAN Manager (vManage) API stub used to
# exercise Correlix's NMS vendor-controller integration cycle end-to-end without
# a real controller. Off by default — started only via the "mock-nms" compose
# profile.
#
# Pinned to the same patched Go toolchain + distroless runtime as the API image.
FROM golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS build
WORKDIR /src
COPY deployment/docker/mock-nms/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mock-nms .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639
COPY --from=build /out/mock-nms /mock-nms
USER nonroot:nonroot
EXPOSE 8091
ENTRYPOINT ["/mock-nms"]
