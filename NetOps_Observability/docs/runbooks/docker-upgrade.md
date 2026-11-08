# Upgrading Docker Engine on a Correlix host

Correlix pins Docker Engine to a **validated** version (tracker 373). Docker's own
UDP conntrack flush is what keeps a device's source address intact when a
telemetry receiver restarts; it was broken in 29.5.0 and remains port-sensitive in
later releases (moby#53384). So the Engine is never "latest", it is held, and an
upgrade is a deliberate, validated step.

- Pin: `DOCKER_CE_VERSION` in `scripts/prepare-host.sh` (installs exactly that
  version, then `apt-mark hold docker-ce docker-ce-cli`).
- Validated list: `VALIDATED_DOCKER_VERSIONS` in `scripts/install_doctor.py`
  (doctor: ok = validated, warn = works but not validated, problem = < 23 or
  exactly 29.5.0). `tests/test_docker_version_pin.py` keeps the two in step.

## A. Validating a new version (Correlix engineering, on the lab)

1. Read the Engine release notes for networking / conntrack / port-publishing changes.
2. Stop Correlix cleanly (`./install-correlix.sh stop`) — the TPM custody sidecar
   must stop cleanly; an unclean stop can lock it out (dictionary-attack lockout).
3. Upgrade, as root:
   `apt-mark unhold docker-ce docker-ce-cli`
   `apt-get install docker-ce=<pkg-version> docker-ce-cli=<pkg-version>`
   (`apt-cache madison docker-ce` lists the exact package versions)
   `apt-mark hold docker-ce docker-ce-cli`
4. Start Correlix (`./install-correlix.sh start`), then run
   `scripts/deploy-qualify.sh` — it must QUALIFY.
5. Source-address drill: while devices are sending, stop a receiver for ~40 s
   and start it again (`docker compose stop syslog-ng; sleep 40; docker compose start syslog-ng`,
   and the same for the trap path). `netops_ingest_source_masked_events` must not
   increase.
6. Only then: add the version to `VALIDATED_DOCKER_VERSIONS`, set the
   `DOCKER_CE_VERSION` default, and ship it in a release with an upgrade note.

## B. Customer upgrade (when a Correlix release raises the pin)

As root, at a quiet moment (telemetry is not received while the Engine restarts):

    ./install-correlix.sh stop
    apt-mark unhold docker-ce docker-ce-cli
    apt-get install docker-ce=<pkg-version> docker-ce-cli=<pkg-version>
    apt-mark hold docker-ce docker-ce-cli
    ./install-correlix.sh start
    python3 scripts/install_doctor.py      # Docker Engine version: ok

An existing Docker that already works is never changed by the installer; the
doctor reports whether it is validated.
