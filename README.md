# tunnel-client

English | [简体中文](README.zh-CN.md)

**End users: see [使用说明.md](使用说明.md) (Chinese, phone / Windows).**

A cross-platform tunnel client whose protocol stack is written in C11. The Linux,
Android and Windows shells all share the same core, so protocol behaviour,
certificate policy and statistics are identical on every platform.

## Supported protocols

| Protocol | Description | Status |
| --- | --- | --- |
| SSTP | MS-SSTP: TCP (443) + TLS + PPP over HDLC + MPPE key exchange / Crypto-Binding | Available |
| L2TP | RFC 2661 control and bearer; IPsec is left to the platform (Windows IPsec / Linux strongSwan) | Available |
| PPTP | RFC 2637 (TCP 1723 control + GRE data plane); **plain PPTP is proven insecure**, the UI must warn about it | Platform dependent |

## Layout

```
core/include/vpncore/  public headers (stable C ABI for shells: vpn_capi.h)
core/src/              protocol implementation
  vpn_client.c         lifecycle: transport selection, PPP cross-callbacks, TUN forwarding, reconnect, stats
  vpn_tls.c            TLS abstraction (OpenSSL 3, swappable for mbedTLS)
  vpn_sstp.c vpn_l2tp.c vpn_pptp.c
  vpn_ppp*.c           LCP / IPCP / CHAP / PAP / frame encapsulation
  vpn_crypto.c vpn_md4.c vpn_des.c   MS-CHAPv2 / MPPE / MD4 / DES
  vpn_tun.c            virtual interface (Linux /dev/net/tun, Android/Windows use external callbacks)
  vpn_net.c            non-blocking sockets (poll / Winsock)
  vpn_capi.c           thin C ABI wrapper (config conversion + callback forwarding)
cli/main.c             Linux command-line client
platform/android/      VpnService + JNI shell
platform/windows/      Wintun + C# shell
tests/                 unit tests (HDLC / MS-CHAPv2 / SSTP packets / L2TP AVPs / C ABI)
```

## Build (Linux)

```bash
sudo apt install build-essential cmake libssl-dev
cmake -S . -B build && cmake --build build -j
cd build && ctest --output-on-failure
```

Outputs: `libvpncore.a`, `libvpncore.so`, `vpn-cli` and the test executables.

## Packaging and release

`scripts/build_windows.sh`, `scripts/build_android.sh` and `scripts/package_all.sh`
produce `dist/tunnel-client-all-<ver>.zip`. `dist/` is not tracked by git; the
bundle is published as a GitHub Release asset:

```bash
GH_TOKEN=<token with Contents: read-write> scripts/package_all.sh 1.4.0
```

The script creates (or reuses) the `v<ver>` release and replaces the asset with
the same name. `SKIP_RELEASE=1` skips the upload and leaves the zip in `dist/`.

## Usage (CLI)

```bash
# Connectivity check only (no TUN, no root required)
./build/vpn-cli -s vpn.example.com -u alice -p secret --no-tun

# Full connection (root required to create the TUN device)
sudo ./build/vpn-cli -s vpn.example.com -u alice -p secret

# L2TP (the IPsec SA must already be established by the system)
sudo ./build/vpn-cli -s vpn.example.com --proto l2tp -u alice -p secret

# Skip certificate validation (self-signed test servers only; a warning is printed)
sudo ./build/vpn-cli -s 10.0.0.1 -u alice -p secret --cert ignore
```

Common options: `--port`, `--proto`, `--mtu`, `--ca-file`, `--cert verify|ignore`,
`--route CIDR` (repeatable), `--keepalive`, `--reconnect-delay`, `--max-retries`,
`--timeout`, `--stats-interval`, `-v/-q`. See `vpn-cli --help` for the full list.

## Certificate policy

- Default **verify**: validates the chain (custom root via `--ca` when given),
  expiry and host name (`SSL_set1_host`), and prints the SHA-256 fingerprint.
- **ignore** (`--cert ignore` / `cert_mode=1`): skips validation but still prints
  the fingerprint; both the CLI and the GUI shells warn explicitly, and the
  switch stays visible so it can be turned back on.
- The minimum TLS version is relaxed to 1.0 with `SECLEVEL=1` for compatibility
  with older implementations such as RouterOS. To enforce modern TLS only,
  change the version settings in `vpn_tls.c`.

## Port rules

| Protocol | Port | Configurable |
|---|---|---|
| SSTP | TCP/443 | **Yes** — the GUI port field is editable, CLI uses `--port N` |
| L2TP | UDP/1701 | **No** — the GUI port field is disabled, `--port` is ignored |
| PPTP | TCP/1723 | **No** — the GUI port field is disabled, `--port` is ignored |

SSTP defaults to 443, which blends in with HTTPS traffic and traverses firewalls
best; when another port is used the CLI/GUI warns that reachability may degrade.

L2TP/PPTP are fixed-port protocols (RouterOS listens on 1701/1723), so the
client does not expose a port setting: even if a config file or `--port` carries
a different value, the core normalises it to the protocol default and logs a
warning.

## Routing and DNS

After a successful connection the client:

1. adds a /32 host route to the server IP through the **original gateway**, so
   the tunnel cannot route into itself;
2. applies the address/mask/DNS assigned by the server over IPCP;
3. removes those routes on teardown.

On Android routing/DNS is handled by `VpnService.Builder`; on Windows the shell
calls netsh/API.

## Protocol availability per platform

| Protocol | Linux | Windows | Android (unrooted) |
|---|---|---|---|
| SSTP (TCP 443/TLS) | ✓ | ✓ | ✓ |
| L2TP (UDP 1701) | ✓ | ✓ | Plain L2TP only; ESP raw sockets are unavailable when IPsec is required |
| PPTP (GRE 47) | ✓ (needs CAP_NET_RAW) | ✓ (WFP) | ✗ cannot create GRE raw sockets |

The PPTP data plane needs a raw socket for IP protocol 47. An unrooted Android
app has no `CAP_NET_RAW`, so `socket(AF_INET, SOCK_RAW, 47)` returns EPERM. The
core therefore reports `false` from `vpn_pptp_supported()` on Android and the
client warns and refuses to connect instead of letting the user connect and
then send nothing.

## Statistics and logging

`vpn_stats` exposes bytes/packets sent and received, drops, reconnect count,
RTT, connection timestamp, local/peer addresses, DNS, cipher suite and
certificate fingerprint. Logging has 5 levels (TRACE/DEBUG/INFO/WARN/ERROR) and
can be redirected to Android logcat / a Windows window via
`vpn_capi_set_log_callback`.

The default level is INFO: only key milestones are printed (TCP, control
channel, call, first GRE packet, LCP ack, authentication, IPCP, connectivity);
per-packet diagnostics are DEBUG only. On Windows this is controlled by the
`debug` key in `vpn-gui.ini`:

```ini
; 1 = per-packet debug logging (troubleshooting), 0 = concise (default)
debug=0
```

The GRE header format must match the peer: `flags=0x3001` (K+S+Ver1) followed by
a 4-byte sequence number after the Call ID. Without the sequence number
(`0x2001`), RouterOS interprets the fields using its own layout, takes
`FF03C021` as the sequence number, and silently drops the misaligned PPP frame —
the symptom is "GRE keeps sending, the peer never answers".

## Platform shells

- Android: see `platform/android/README.md` (two-phase tunnel setup with VpnService)
- Windows: see `platform/windows/README.md` (callback-based TUN over Wintun)

## Known limitations

- The PPTP data plane needs a GRE raw socket, which most platforms disable by
  default; the core reports it as unsupported via `vpn_pptp_supported()`.
- L2TP implements plain L2TPv2 only; IPsec must be provided by the system or a
  separate IKE process.
- MPPE only derives keys for SSTP Crypto-Binding. Encrypting the L2TP data plane
  with MPPE would require RC4 handling (40/56/128-bit) in `vpn_ppp_rx/tx`.
- Unit tests do not need a real server; end-to-end testing requires a working
  SSTP/L2TP endpoint.

## Third-party components

The project's own code (including `core/`, `cli/`, `platform/`, `tests/` and the
in-house generated `app.ico`) is original work. The distributed binaries contain
or link against the following third-party components:

| Component | Used by | License |
|---|---|---|
| Wintun 0.14.1 (`wintun.dll`, official signed amd64 build) | Windows | Wintun Prebuilt Binaries License |
| OpenSSL 3.0.2 | Linux (dynamic), Android/Windows (static) | Apache-2.0 |
| Android NDK / libc++ / Kotlin stdlib | Android | Apache-2.0 |

Wintun is used strictly through its published API (`wintun.h`); it is not
modified. Wintun™ is a trademark of WireGuard LLC, and this project is not
affiliated with or endorsed by the WireGuard project. Full texts are in
`LICENSES/` and in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md); release
bundles carry the same notices next to the binaries (the Android app shows them
under "About → Third-party").

## License

MIT License - see [LICENSE](LICENSE). You may use, modify, distribute and
sublicense this software, including commercially, provided the copyright notice
and permission notice are retained. Third-party components remain under their
own licenses as listed above.
