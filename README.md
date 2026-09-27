# netmap: live LAN topology

Scans your local network, fingerprints every device, and draws a live topology in the browser.
Runs on Linux and macOS with Python 3.8+ only: no pip install, no build step.

```bash
./netmap.py serve                 # http://127.0.0.1:8765
./netmap.py scan                  # one-shot table in the terminal
./netmap.py scan --json | jq .    # scriptable
./netmap.py update-oui            # optional: full IEEE vendor DB (nmap/wireshark DBs are used if installed)
python3 test_netmap.py            # parser self-check
```

Options (`serve` / `scan`): `--iface en0`, `--cidr 10.0.0.0/22` (max 4096 addrs), `--no-ports`,
`--no-traceroute`, `--interval 60`. For `serve` only: `--bind`, `--port`.

## What it does

| | |
|---|---|
| **Discovery** | ICMP sweep + ARP/neighbour table + TCP probe. Status is `online`, `stale` (only in the ARP cache) or `offline`. |
| **Fingerprint** | MAC, vendor (OUI), randomized-MAC detection, reverse DNS, 36 common TCP ports, device-type guess (router/printer/phone/camera/IoT/…). |
| **Topology** | Internet → traceroute hops (ISP path) → gateway → devices. Edge colour = latency, WAN edge width/animation = live throughput. Drag to pin, double-click to unpin, zoom/pan. |
| **Activity** | Live established TCP connections of this host (process → remote host:port, rDNS), optionally drawn on the graph. Interface ↓/↑ rate + sparkline. |
| **Alerts** | New device, went offline/back online, MAC changed for an IP, one MAC answering for several IPs (flags possible ARP spoofing when it's the gateway's MAC). |
| **Deep probe** | Per device: ping ×5 stats, traceroute, TCP 1–1024 scan. Restricted to the scanned subnet. |
| **Inventory** | Labels and notes per device, first/last seen, persisted per network (subnet + gateway MAC) in `~/.netmap/` (`NETMAP_HOME` overrides). |
| **Integrations** | `GET /api/state` (JSON), `/api/export.csv`, `/metrics` (Prometheus), `POST /api/scan`. UI exports JSON/CSV/SVG. |

Keys: `/` filter, `r` rescan.

## Notes

- **macOS:** apps need *Local Network* permission to see MAC addresses and the ARP table. Homebrew's
  Python usually doesn't have it, and netmap shows a banner when it's missing. Either grant it in System Settings →
  Privacy & Security → Local Network, or run with `/usr/bin/python3 netmap.py serve`.
- No root needed. Without root, the connection list only includes your own user's processes.
- It binds to `127.0.0.1` by default. `--bind 0.0.0.0` exposes the inventory and the scan trigger to your LAN.
  Host-header and JSON-content-type checks block DNS-rebinding and CSRF from other websites.
- Only scan networks you own or are authorized to test.
- Not included: per-device traffic volumes (needs packet capture/root or SNMP/NetFlow from the switch/router),
  LLDP/CDP switch-port mapping, IPv6 neighbour discovery.
