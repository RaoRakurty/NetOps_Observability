# tgen — lab traffic generator. Stdlib-only core (no pip deps required for the
# flow-telemetry + raw-packet + L7-session modes), so the image is tiny and
# builds offline.
FROM python:3.12-slim

# tcpdump/iproute2 handy for in-container verification; optional.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 tcpdump ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY tgen/ /app/tgen/
COPY config.yaml /app/config.yaml

ENV PYTHONUNBUFFERED=1
# Defaults; override at `docker run`. IPFIX to the NMS collector forever.
ENTRYPOINT ["python", "-m", "tgen"]
CMD ["--mode", "all", "--collector", "10.70.245.122", "--fps", "1500", "--workers", "2"]
