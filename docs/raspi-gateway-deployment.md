# Raspberry Pi vessel-gateway deployment runbook

Target hardware: Raspberry Pi 4/5 (`aarch64`) or Pi 3 (`armv7`) on the vessel,
running the `gateway` binary and a Wazuh agent. The gateway ingests AIS NMEA
0183 (TCP/serial bridge), LoRaWAN sensor uplinks (network-server JSON-lines
bridge), and emits `TelemetryFrame`s to `ferries.telemetry.v1` via the
configured transport, spooling to `/var/lib/blueeconomy/journal` whenever the
uplink is down.

## 1. Cross-compile

From an x86_64 build host with rustup:

```bash
# Pi 4/5, 64-bit OS
rustup target add aarch64-unknown-linux-gnu
# Pi 3 / 32-bit OS
rustup target add armv7-unknown-linux-gnueabihf

sudo apt-get install gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf pkg-config
```

`.cargo/config.toml` (build host, not committed — runner-specific paths):

```toml
[target.aarch64-unknown-linux-gnu]
linker = "aarch64-linux-gnu-gcc"
[target.armv7-unknown-linux-gnueabihf]
linker = "arm-linux-gnueabihf-gcc"
```

Build the locked binary with exactly one transport feature:

```bash
# Primary: Fluvio producer (vendored OpenSSL TLS + native compression).
cargo build --locked --release --features fluvio-transport \
  --target aarch64-unknown-linux-gnu --bin gateway

# Fallback: blocking Kafka producer (small dependency tree, no TLS stack).
cargo build --locked --release --features kafka-transport \
  --target aarch64-unknown-linux-gnu --bin gateway
```

Notes:

- The default (no-feature) build compiles everywhere with Rust 1.75+ but has
  **no uplink transport compiled in**; selecting a transport in
  configuration then fails closed with `transport_unavailable`. Always ship a
  transport feature in deployment artifacts.
- `fluvio-transport` compiles vendored OpenSSL; on cross builds this requires
  the target C toolchain above (no sysroot OpenSSL needed). If the site
  prohibits C builds, use `kafka-transport`.
- Reproducibility is anchored by `Cargo.lock`; never build with
  `--offline`-edited manifests.

## 2. Host layout

| Path | Purpose |
|------|---------|
| `/opt/blueeconomy/bin/gateway` | gateway binary (FIM-monitored) |
| `/etc/blueeconomy/gateway.env` | environment configuration (FIM-monitored) |
| `/var/lib/blueeconomy/journal` | local spool journal (FIM-monitored) |
| `/var/log/blueeconomy/gateway.log` | JSON event log (Wazuh localfile) |

```bash
sudo install -d -m 0750 -o blueeco -g blueeco /var/lib/blueeconomy/journal
sudo install -d -m 0755 /etc/blueeconomy /var/log/blueeconomy
sudo install -m 0755 target/aarch64-unknown-linux-gnu/release/gateway \
  /opt/blueeconomy/bin/gateway
```

## 3. Configuration (`/etc/blueeconomy/gateway.env`)

```ini
GATEWAY_ID=gw-vessel-014
VESSEL_DEVICE_ID=vessel-014
JOURNAL_DIR=/var/lib/blueeconomy/journal
UPLINK_TRANSPORT=fluvio            # or kafka (config-only swap)
UPLINK_ENDPOINT=                   # fluvio: empty = profile; kafka: host:9092,...
TELEMETRY_TOPIC=ferries.telemetry.v1
DATA_CLASSIFICATION=internal
AIS_LISTEN_ADDR=127.0.0.1:10110    # AIS receiver NMEA TCP feed
SENSOR_LISTEN_ADDR=127.0.0.1:10111 # LoRaWAN bridge JSON-lines feed
HEARTBEAT_INTERVAL_SECONDS=30
LATENESS_WINDOW_SECONDS=300        # keep aligned with the 5-minute freshness KPI
```

Permissions: `0640 root:blueeco`. The gateway refuses to start on invalid or
incomplete configuration (exit code 2).

## 4. systemd unit (`/etc/systemd/system/blueeconomy-gateway.service`)

```ini
[Unit]
Description=Blue Economy vessel edge gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=blueeco
Group=blueeco
EnvironmentFile=/etc/blueeconomy/gateway.env
ExecStart=/opt/blueeconomy/bin/gateway
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blueeconomy/journal /var/log/blueeconomy
StandardOutput=append:/var/log/blueeconomy/gateway.log
StandardError=append:/var/log/blueeconomy/gateway.log

[Install]
WantedBy=multi-user.target
```

The gateway fails closed: a corrupt journal (`journal_corruption`) or an
unavailable transport stops the unit; do not mask this with `Restart=always`
without paging the operator — Wazuh rule 100105 fires on the halt.

## 5. Wazuh agent

1. Install the Wazuh agent package for the Pi architecture from the Wazuh
   package repository (`armhf`/`arm64` debs), enrol against the manager per
   the blueeconomy-security-operations enrolment SOP.
2. Append `wazuh/ossec.conf.fragment.xml` into the agent `<ossec_config>`.
3. Copy `wazuh/rules/waterway-gateway-rules.xml` to the manager's
   `/var/ossec/etc/rules/` and reload the manager ruleset. Rule IDs 100101+
   are reserved for this gateway ruleset; changes follow the
   detection-engineering lifecycle in blueeconomy-security-operations.
4. Verify: emit one malformed NMEA line into the AIS feed and confirm rule
   100101 fires; touch `/etc/blueeconomy/gateway.env` and confirm rule
   100107 fires.

## 6. Recovery drill (intermittent corridor profile)

1. Stop the uplink (block egress or stop the Fluvio/Kafka endpoint).
2. Confirm the gateway logs `uplink_failed_spooled` and heartbeat frames
   report `uplink_available: false`; journal bytes grow.
3. Restore the uplink. On the next heartbeat tick the gateway replays the
   journal oldest-first and truncates segments only after each batch is
   acknowledged. `journal_replay_progress` events confirm the drain.
4. If `journal_corruption` appears instead, the gateway halted closed: quarantine
   `/var/lib/blueeconomy/journal` for forensics, then re-initialise an empty
   journal directory. Never hand-edit segment files.
