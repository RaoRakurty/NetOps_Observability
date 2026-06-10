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
# Pre-built dashboard (deploy.sh runs `npm run build` before shipping).
COPY webui/dist/ /app/webui/dist/

ENV PYTHONUNBUFFERED=1
EXPOSE 8080
# Defaults; override at `docker run`. Serve mode = control API + dashboard on
# :8080, autostarts all three telemetry encoders at the NMS collector.
ENTRYPOINT ["python", "-m", "tgen"]
CMD ["--serve", "--collector", "10.70.245.122", "--fps", "1500", "--workers", "2"]
