# mdns-relay

A lightweight, high-performance **mDNS (multicast DNS) relay** written in Rust.

It forwards mDNS packets between network interfaces for both **IPv4 and IPv6**, enabling service discovery across isolated subnets — ideal for **Matter**, **HomeKit**, and other protocols that rely on link-local multicast.

---

## ✨ Features

* 📡 Supports IPv4 (`224.0.0.251`) and IPv6 (`ff02::fb`)
* 🔁 Interface-to-interface forwarding with unidirectional or bidirectional configuration
* 🧠 Loop prevention with TTL-based deduplication cache
* 🔧 Clean, TOML-based configuration (config-driven architecture)
* ⚡ Single-threaded `tokio` async runtime
* 🖥️ Native systemd support for Linux
* 🐳 Docker-ready with multi-arch support (x86\_64, ARM64, ARMv7)
* 📊 Runtime statistics logging for packet processing

---

## 🚀 Quick Start

### Requirements

* Linux (with multicast + `NET_RAW` support)
* Docker (for container usage; host networking required)
* `systemd` (for native service management)

### Install & Run

```bash
# Build or download binary
make build

# Copy config and binary
sudo cp target/x86_64-unknown-linux-musl/release/mdns-relay /usr/local/bin/
sudo cp etc/mdns-relay.toml /etc/

# Run manually (uses /etc/mdns-relay.toml)
mdns-relay

# Show version or help
mdns-relay --version
mdns-relay --help
```

---

## 🔧 Configuration (`/etc/mdns-relay.toml`)

The service is fully config-driven using a TOML file.

By default, it loads `/etc/mdns-relay.toml`, but this path can be overridden via `--config`.

➡️ See the full documented config file at [`etc/mdns-relay.toml`](./etc/mdns-relay.toml) for all supported options and examples.

```toml
# Interface bridging
[[interface]]
src = "eth0"
dst = "wlan0"
stack = "dual"

[[interface]]
src = "wlan0"
dst = "eth0"
stack = "dual"

# TTL-based cache to prevent loops
ttl = 10
cache_size = 1000

# Logging
log_level = "info"
log_format = "pretty"

# Performance tuning
buffer_size = 2048
max_events = 64
loop_detection_ms = 200
stats_interval_seconds = 300
cleanup_interval_seconds = 30
max_packet_size = 9000
```

> 🔍 See [example configurations](#-example-configurations) for VLANs, Docker, and Proxmox setups.

---

## 🖥️ Run as systemd Service (Linux)

```bash
# Install binary + service
make install

# Start service
sudo systemctl enable --now mdns-relay
sudo systemctl status mdns-relay

# Logs
sudo journalctl -u mdns-relay -f
```

---

## 🐳 Run with Docker

```bash
docker build -t mdns-relay .

docker run --rm --net=host --cap-add=NET_RAW \
  -v /etc/mdns-relay.toml:/etc/mdns-relay.toml:ro \
  mdns-relay:latest
```

### Docker Compose

```yaml
version: '3.8'

services:
  mdns-relay:
    build: .
    image: engeloded/mdns-relay:latest
    network_mode: host
    cap_add: [NET_RAW]
    volumes:
      - /etc/mdns-relay.toml:/etc/mdns-relay.toml:ro
    restart: unless-stopped
```

> 💡 The `:latest` tag is a multi-arch manifest (x86\_64, arm64, armv7).
> You can also pull a specific image like:
>
> ```bash
> docker pull engeloded/mdns-relay:1.0.0-aarch64-unknown-linux-musl
> ```

---

## 🏗️ Build from Source

```bash
# Build for your native system
make build

# Build for ARM64 (RPi 4+)
make build TARGET=aarch64-unknown-linux-musl

# Build for ARMv7 (RPi 3)
make build TARGET=armv7-unknown-linux-musleabihf

# Build for all supported platforms
make build-all
```

---

## 🔍 Command Line Options

```bash
mdns-relay --help
```

```
Usage: mdns-relay [OPTIONS]

Options:
  -c, --config <FILE>  Configuration file path [default: /etc/mdns-relay.toml]
  -v, --version        Print version information
  -h, --help           Print help
```

---

## 🧰 Example Configurations

### HomeKit or Matter Across Wi-Fi & Ethernet

```toml
[[interface]]
src = "eth0"
dst = "wlan0"
stack = "dual"

[[interface]]
src = "wlan0"
dst = "eth0"
stack = "dual"
```

### Bridging VLANs

```toml
[[interface]]
src = "eth0"
dst = "eth0.100"
stack = "ipv4"
```

### Docker Host + LAN

```toml
[[interface]]
src = "docker0"
dst = "eth0"
stack = "ipv4"
```

### Proxmox or Hypervisor Networks

```toml
[[interface]]
src = "vmbr0"
dst = "eth0"
stack = "dual"
```

---

## 🥮 Troubleshooting

### Debug Mode

```toml
log_level = "debug"

[[interface]]
src = "eth0"
dst = "eth1"
stack = "dual"
```

```bash
mdns-relay --config debug.toml
```

### mDNS Discovery

```bash
# View services
avahi-browse -a
dns-sd -B _services._dns-sd._udp
```

### Log Monitoring

```bash
# systemd logs
sudo journalctl -u mdns-relay -f

# Docker logs
docker logs -f mdns-relay
```

---

## 🧠 Best Practices

* Use `stack = "dual"` for maximum compatibility
* Use bidirectional interface definitions (src → dst and dst → src)
* Always verify interface names via `ip link show`
* Ensure Docker runs with `--net=host --cap-add=NET_RAW`
* Test with `log_level = "debug"` to confirm packet flow

---

## 📦 Docker Images

Published with `make release`, tags include:

* `engeloded/mdns-relay:latest` – multi-arch (auto-selects arch)
* `engeloded/mdns-relay:<version>-<target>` – arch-specific

Supported targets:

* `x86_64-unknown-linux-musl`
* `aarch64-unknown-linux-musl`
* `armv7-unknown-linux-musleabihf`
* `i686-unknown-linux-musl`

---

## 📜 License

MIT License — see [LICENSE](./LICENSE)

---

## ✍️ Author

Created by **Engel Oded**
Contributions and feedback welcome!

---
