# vm-image-builder — containerized toolchain for building the Correlix
# appliance VM images (qcow2 / vmdk / vhdx) so the HOST needs nothing but
# Docker (#97 VM leg, owner directive 2026-07-18). libguestfs does the image
# surgery in a userspace appliance — no kvm/root required (slower without
# /dev/kvm, still correct).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive LIBGUESTFS_BACKEND=direct
RUN apt-get update && apt-get install -y --no-install-recommends \
      qemu-utils libguestfs-tools cloud-image-utils \
      linux-image-generic ca-certificates curl xz-utils zstd \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
