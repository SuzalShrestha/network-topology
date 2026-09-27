#!/usr/bin/env python3
"""netmap — LAN discovery + live topology for Linux/macOS. Python 3.8+ stdlib only.

  ./netmap.py serve            # web UI on http://127.0.0.1:8765
  ./netmap.py scan [--json]    # one-shot scan to stdout
  ./netmap.py update-oui       # download IEEE vendor DB
"""
import argparse, collections, concurrent.futures as cf, csv, io, ipaddress, json, os, platform, re
import socket, subprocess, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

MAC_OS = platform.system() == "Darwin"
HERE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("NETMAP_HOME", Path.home() / ".netmap"))
PORTS = [21, 22, 23, 25, 53, 80, 81, 88, 110, 139, 143, 443, 445, 515, 548, 554, 631, 1883, 3000, 3306,
         3389, 5000, 5432, 5900, 6379, 7000, 8000, 8008, 8009, 8080, 8443, 8888, 9000, 9100, 32400, 62078]
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def norm_mac(m):
    return ":".join(p.zfill(2) for p in m.lower().split(":"))


# ---------- parsers (pure, tested in test_netmap.py) ----------

def parse_arp(text):
    """`arp -an` (macOS) or `ip neigh` (Linux) -> {ip: mac}."""
    out = {}
    for line in text.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{11,17})", line) or \
            re.search(r"^(\d+\.\d+\.\d+\.\d+) .*lladdr ([0-9a-fA-F:]{17})", line)
        if m and "FAILED" not in line:
            mac = norm_mac(m.group(2))
            if mac != "ff:ff:ff:ff:ff:ff" and not mac.startswith("01:00:5e"):
                out[m.group(1)] = mac
    return out


def parse_ping(text):
    m = re.search(r"time[=<]([\d.]+)", text)
    return float(m.group(1)) if m else None


def split_hostport(s):
    host, port = s.rsplit(":", 1)
    host = host.strip("[]")
    return (host[7:] if host.startswith("::ffff:") else host), int(port)


def parse_lsof(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+(\d+)\s.*TCP (\S+)->(\S+) \(ESTABLISHED\)", line)
        if m:
            (lh, lp), (rh, rp) = split_hostport(m.group(3)), split_hostport(m.group(4))
            out.append({"proc": m.group(1).replace("\\x20", " "), "pid": int(m.group(2)),
                        "local": lh, "lport": lp, "remote": rh, "rport": rp})
    return out


def parse_ss(text):
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 4 or f[0] == "Recv-Q":
            continue
        p = re.search(r'\("([^"]+)",pid=(\d+)', line)
        (lh, lp), (rh, rp) = split_hostport(f[2]), split_hostport(f[3])
        out.append({"proc": p.group(1) if p else "?", "pid": int(p.group(2)) if p else None,
                    "local": lh, "lport": lp, "remote": rh, "rport": rp})
    return out


def parse_traceroute(text):
    hops = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+(\S+)(?:\s+([\d.]+) ms)?", line)
        if m:
            hops.append({"hop": int(m.group(1)), "ip": None if m.group(2) == "*" else m.group(2),
                         "rtt": float(m.group(3)) if m.group(3) else None})
    return hops


def parse_iface_bytes(text, iface, mac_os=MAC_OS):
    """`netstat -ibn` (macOS) or /proc/net/dev (Linux) -> (rx_bytes, tx_bytes)."""
    for line in text.splitlines():
        if mac_os:
            f = line.split()
            if len(f) > 7 and f[0] == iface and f[2].startswith("<Link#"):
                return int(f[-5]), int(f[-2])
        elif line.strip().startswith(iface + ":"):
            f = line.split(":", 1)[1].split()
            return int(f[0]), int(f[8])
    return None


# ---------- system probes ----------

def default_route():
    """-> (gateway_ip, interface)."""
    if MAC_OS:
        t = run(["route", "-n", "get", "default"])
        gw, dev = re.search(r"gateway:\s*(\S+)", t), re.search(r"interface:\s*(\S+)", t)
        return (gw.group(1) if gw else None), (dev.group(1) if dev else None)
    m = re.search(r"default via (\S+) dev (\S+)", run(["ip", "route", "show", "default"]))
    return (m.group(1), m.group(2)) if m else (None, None)


def iface_info(iface):
    """-> (ip, network, mac) of an interface."""
    if MAC_OS:
        t = run(["ifconfig", iface])
        m = re.search(r"inet (\S+) netmask (0x[0-9a-f]+)", t)
        if not m:
            return None, None, None
        ip, prefix = m.group(1), bin(int(m.group(2), 16)).count("1")
        mac = re.search(r"ether ([0-9a-f:]{17})", t)
    else:
        m = re.search(r"inet (\S+)/(\d+)", run(["ip", "-o", "-4", "addr", "show", "dev", iface]))
        if not m:
            return None, None, None
        ip, prefix = m.group(1), int(m.group(2))
        mac = re.search(r"link/\S+ ([0-9a-f:]{17})", run(["ip", "-o", "link", "show", "dev", iface]))
    mac = mac.group(1) if mac and mac.group(1) != "02:00:00:00:00:00" else None  # macOS redacts w/o permission
    return ip, ipaddress.ip_network(f"{ip}/{prefix}", strict=False), mac


def arp_table():
    return parse_arp(run(["arp", "-an"]) if MAC_OS else run(["ip", "neigh"]))


def ping(ip, count=1):
    return parse_ping(run(["ping", "-c", str(count), "-W", "1000" if MAC_OS else "1", ip], timeout=count + 3))


def tcp_open(host_port, timeout=0.5):
    with socket.socket() as s:
        s.settimeout(timeout)
        return s.connect_ex(host_port) == 0


def port_scan(hosts, ports=PORTS):
    pairs = [(h, p) for h in hosts for p in ports]
    res = collections.defaultdict(list)
    with cf.ThreadPoolExecutor(100) as ex:  # macOS default ulimit -n is 256
        for (h, p), ok in zip(pairs, ex.map(tcp_open, pairs)):
            if ok:
                res[h].append(p)
    return res


def rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def connections():
    if not MAC_OS and run(["which", "ss"]).strip():
        conns = parse_ss(run(["ss", "-tnpH", "state", "established"]))
    else:
        conns = parse_lsof(run(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"]))
    return [c for c in conns if not ipaddress.ip_address(c["remote"]).is_loopback]


def iface_bytes(iface):
    text = run(["netstat", "-ibn"]) if MAC_OS else Path("/proc/net/dev").read_text()
    return parse_iface_bytes(text, iface)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return {62078: "iphone-sync", 32400: "plex", 8009: "chromecast", 1883: "mqtt", 7000: "airplay"}.get(port, "")


# ---------- vendor / type ----------

_oui = None


def vendor(mac):
    global _oui
    if not mac:
        return None
    if int(mac[1], 16) & 2:
        return "Private (randomized MAC)"
    if _oui is None:
        _oui = {}
        for p in [DATA / "oui.txt", Path("/usr/share/ieee-data/oui.txt"), Path("/usr/share/wireshark/manuf"),
                  Path("/opt/homebrew/share/wireshark/manuf"), Path("/usr/local/share/wireshark/manuf"),
                  Path("/opt/homebrew/share/nmap/nmap-mac-prefixes"), Path("/usr/local/share/nmap/nmap-mac-prefixes"),
                  Path("/usr/share/nmap/nmap-mac-prefixes")]:
            if p.exists():
                for line in p.read_text(errors="ignore").splitlines():
                    m = re.match(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+)$", line)
                    if m:
                        _oui[":".join(m.groups()[:3]).lower()] = m.group(4).strip()
                    elif re.match(r"^[0-9A-F]{6} ", line):  # nmap
                        _oui.setdefault(":".join(re.findall("..", line[:6])).lower(), line[7:].strip())
                    elif re.match(r"^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}\t", line):
                        f = line.split("\t")
                        _oui[f[0].lower()] = (f[2] if len(f) > 2 else f[1]).strip()
    return _oui.get(mac[:8])


def guess_type(d):
    ports, v = set(d.get("ports") or []), (d.get("vendor") or "").lower()
    if d.get("is_self"): return "this-host"
    if d.get("is_gateway"): return "router"
    if ports & {9100, 631, 515}: return "printer"
    if 62078 in ports or "randomized" in v: return "phone"
    if ports & {8008, 8009, 32400} or re.search(r"roku|sonos|vizio|lg elec|tcl", v): return "media"
    if 554 in ports or re.search(r"hikvision|dahua|axis|reolink|wyze", v): return "camera"
    if re.search(r"espressif|tuya|shelly|sonoff|nest|ecobee|philips|signify", v) or 1883 in ports: return "iot"
    if re.search(r"ubiquiti|cisco|netgear|tp-link|aruba|mikrotik|juniper|eero|arris", v): return "network"
    if ports & {3389, 445, 139, 548, 5900}: return "computer"
    if ports & {22, 3306, 5432, 6379}: return "server"
    if re.search(r"apple|dell|lenovo|hewlett|intel|asus|microsoft|raspberry", v): return "computer"
    return "unknown"


# ---------- engine ----------

class Netmap:
    def __init__(self, a):
        self.a, self.lock, self.wake = a, threading.Lock(), threading.Event()
        self.devices, self.events, self.key = {}, collections.deque(maxlen=500), None
        self.meta, self.path, self.conns = {"scanning": False, "last_scan": None}, [], []
        self.traffic = {"rx_bps": 0, "tx_bps": 0, "history": collections.deque(maxlen=150)}
        self.names, self.pool = {}, cf.ThreadPoolExecutor(8)
        self.warned_dups = set()

    def event(self, level, msg, ip=None):
        self.events.append({"t": time.time(), "level": level, "msg": msg, "ip": ip})

    # inventory is per network (gateway MAC), so a laptop moving between LANs doesn't mix them
    def _file(self):
        return DATA / f"inventory-{re.sub(r'[^0-9a-zA-Z.]', '_', self.key)}.json"

    def save(self):
        DATA.mkdir(parents=True, exist_ok=True)
        tmp = self._file().with_suffix(".tmp")
        tmp.write_text(json.dumps({"devices": self.devices, "events": list(self.events)}))
        tmp.replace(self._file())

    def load(self, key):
        if self.key:
            self.save()
        self.key, self.devices, self.warned_dups = key, {}, set()
        self.events.clear()
        try:
            d = json.loads(self._file().read_text())
            self.devices = d["devices"]
            self.events.extend(d["events"])
            for dev in self.devices.values():
                dev["status"] = "offline"
        except (OSError, ValueError, KeyError):
            pass

    def scan(self):
        a = self.a
        gw, iface = default_route()
        iface = a.iface or iface
        if not iface:
            raise SystemExit("no default route / interface found; pass --iface")
        my_ip, net, my_mac = iface_info(iface)
        net = ipaddress.ip_network(a.cidr, strict=False) if a.cidr else net
        if not net:
            raise SystemExit(f"no IPv4 address on {iface}")
        if net.num_addresses > 4096:
            raise SystemExit(f"{net} is too large (>4096 addresses); pass a smaller --cidr")
        with self.lock:
            self.meta.update(scanning=True, iface=iface, ip=my_ip, cidr=str(net), gateway=gw,
                             hostname=socket.gethostname(), os=platform.system(), interval=a.interval)
        hosts = [str(h) for h in net.hosts()]
        with cf.ThreadPoolExecutor(64) as ex:
            rtts = dict(zip(hosts, ex.map(ping, hosts)))
        arp = arp_table()
        found = {h for h, r in rtts.items() if r is not None} | {h for h in arp if h in rtts} | {my_ip}
        open_ports = port_scan(found) if not a.no_ports else {}
        with cf.ThreadPoolExecutor(32) as ex:
            names = dict(zip(found, ex.map(rdns, found)))
        names[my_ip] = names.get(my_ip) or socket.gethostname()
        if a.traceroute:
            self.path = parse_traceroute(run(["traceroute", "-n", "-m", "12", "-q", "1", "-w", "1", "1.1.1.1"], 40))

        now = time.time()
        with self.lock:
            key = f"{net}-{arp.get(gw, 'nogw')}"
            if key != self.key:
                self.load(key)
            for h in found:
                d, new = self.devices.get(h), h not in self.devices
                if new:
                    d = self.devices[h] = {"ip": h, "first_seen": now, "label": "", "notes": ""}
                mac = my_mac if h == my_ip else arp.get(h)
                if mac and d.get("mac") and d["mac"] != mac:
                    self.event("warn", f"{h} MAC changed {d['mac']} -> {mac} (IP reuse, conflict or spoofing)", h)
                seen = [s for s, ok in (("icmp", rtts.get(h) is not None), ("arp", h in arp),
                                        ("tcp", bool(open_ports.get(h)))) if ok]
                online = h == my_ip or "icmp" in seen or "tcp" in seen
                prev = d.get("status")
                d.update(mac=mac or d.get("mac"), hostname=names.get(h) or d.get("hostname"), rtt=rtts.get(h),
                         seen_by=seen, is_self=h == my_ip, is_gateway=h == gw,
                         status="online" if online else "stale")  # stale = only in ARP cache, may be gone
                d["vendor"] = vendor(d["mac"])
                if not a.no_ports:
                    d["ports"] = sorted(open_ports.get(h, []))
                d["type"] = guess_type(d)
                if online:
                    d["last_seen"] = now
                if new:
                    self.event("info", f"New device {h} {d['mac'] or ''} {d['vendor'] or ''}".strip(), h)
                elif prev == "offline" and online:
                    self.event("info", f"{h} back online", h)
            for h, d in self.devices.items():
                if h not in found and d.get("status") != "offline":
                    d["status"] = "offline"
                    self.event("info", f"{h} went offline", h)
            by_mac = collections.defaultdict(list)
            for d in self.devices.values():
                if d.get("mac") and d["status"] != "offline":
                    by_mac[d["mac"]].append(d["ip"])
            for mac, ips in by_mac.items():
                if len(ips) > 1 and (mac, tuple(ips)) not in self.warned_dups:
                    self.warned_dups.add((mac, tuple(ips)))
                    gwnote = " — includes gateway MAC: possible ARP spoofing!" if arp.get(gw) == mac else ""
                    self.event("warn", f"MAC {mac} answers for {', '.join(ips)}{gwnote}")
            if MAC_OS and not arp and len(found) > 1:
                self.meta["error"] = (f"macOS is hiding ARP/MAC data from {sys.executable}. Grant it Local Network access "
                                      "(System Settings > Privacy & Security > Local Network) or run with /usr/bin/python3.")
            else:
                self.meta.pop("error", None)
            self.meta.update(scanning=False, last_scan=now)
            self.save()

    def tick(self, prev):
        """Fast loop: interface throughput + live connections."""
        iface = self.meta.get("iface")
        if not iface:
            return prev
        now, b = time.time(), iface_bytes(iface)
        conns = connections()
        for c in conns:
            if c["remote"] not in self.names:
                self.names[c["remote"]] = None
                self.pool.submit(lambda ip: self.names.__setitem__(ip, rdns(ip)), c["remote"])
        with self.lock:
            if b and prev:
                dt = now - prev[0]
                rx, tx = max(0, (b[0] - prev[1][0]) / dt), max(0, (b[1] - prev[1][1]) / dt)
                self.traffic.update(rx_bps=rx, tx_bps=tx)
                self.traffic["history"].append([now, rx, tx])
            self.conns = conns
        return (now, b) if b else prev

    def snapshot(self):
        with self.lock:
            return {"meta": dict(self.meta), "devices": sorted(self.devices.values(), key=lambda d: ipaddress.ip_address(d["ip"])),
                    "path": self.path, "events": list(self.events)[-200:],
                    "traffic": {**self.traffic, "history": list(self.traffic["history"])},
                    "conns": [{**c, "rname": self.names.get(c["remote"])} for c in self.conns]}

    def probe(self, ip):
        with cf.ThreadPoolExecutor(3) as ex:
            p = ex.submit(run, ["ping", "-c", "5", ip], 15)
            t = ex.submit(run, ["traceroute", "-n", "-m", "15", "-q", "1", "-w", "1", ip], 40)
            ports = ex.submit(port_scan, [ip], sorted(set(range(1, 1025)) | set(PORTS)))
            p, t, ports = p.result(), t.result(), ports.result().get(ip, [])
        summary = [l for l in p.splitlines() if "packet" in l or "min/" in l]
        return {"ip": ip, "ping": "\n".join(summary), "traceroute": parse_traceroute(t),
                "ports": [{"port": x, "service": service_name(x)} for x in ports]}

    def loops(self):
        def scanner():
            while True:
                try:
                    self.scan()
                except SystemExit as e:
                    with self.lock:
                        self.meta.update(scanning=False, error=str(e))
                except Exception as e:  # keep the server alive; surface it in the UI
                    with self.lock:
                        self.meta["scanning"] = False
                        self.event("error", f"scan failed: {e!r}")
                self.wake.wait(self.a.interval)
                self.wake.clear()

        def ticker():
            prev = None
            while True:
                try:
                    prev = self.tick(prev)
                except Exception as e:
                    print("tick:", e, file=sys.stderr)
                time.sleep(2)

        for f in (scanner, ticker):
            threading.Thread(target=f, daemon=True).start()


# ---------- HTTP ----------

def metrics(s):
    esc = lambda v: str(v or "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    out = [f'netmap_devices{{status="{st}"}} {sum(d["status"] == st for d in s["devices"])}'
           for st in ("online", "stale", "offline")]
    for d in s["devices"]:
        lbl = f'ip="{d["ip"]}",mac="{esc(d.get("mac"))}",hostname="{esc(d.get("label") or d.get("hostname"))}",type="{d.get("type")}"'
        out.append(f'netmap_device_up{{{lbl}}} {int(d["status"] == "online")}')
        if d.get("rtt") is not None:
            out.append(f'netmap_device_rtt_ms{{ip="{d["ip"]}"}} {d["rtt"]}')
    out += [f'netmap_iface_rx_bytes_per_second {s["traffic"]["rx_bps"]:.0f}',
            f'netmap_iface_tx_bytes_per_second {s["traffic"]["tx_bps"]:.0f}',
            f'netmap_established_connections {len(s["conns"])}']
    return "\n".join(out) + "\n"


def to_csv(s):
    buf = io.StringIO()
    cols = ["ip", "status", "label", "hostname", "mac", "vendor", "type", "rtt", "ports", "first_seen", "last_seen", "notes"]
    w = csv.DictWriter(buf, cols, extrasaction="ignore")
    w.writeheader()
    for d in s["devices"]:
        w.writerow({**d, "ports": " ".join(map(str, d.get("ports") or []))})
    return buf.getvalue()


def make_handler(nm, loopback):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, body, ctype="application/json"):
            body = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def ok_host(self):  # blocks DNS-rebinding when bound to loopback
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            return not loopback or host in ("127.0.0.1", "localhost", "[::1]")

        def do_GET(self):
            if not self.ok_host():
                return self.send(403, {"error": "bad host"})
            u = urlparse(self.path)
            if u.path == "/":
                return self.send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            if u.path == "/api/state":
                return self.send(200, nm.snapshot())
            if u.path == "/api/export.csv":
                return self.send(200, to_csv(nm.snapshot()), "text/csv")
            if u.path == "/metrics":
                return self.send(200, metrics(nm.snapshot()), "text/plain; version=0.0.4")
            if u.path == "/api/probe":
                ip = (parse_qs(u.query).get("ip") or [""])[0]
                try:
                    inside = ipaddress.ip_address(ip) in ipaddress.ip_network(nm.meta.get("cidr"))
                except (ValueError, TypeError):
                    inside = False
                if not inside:  # don't become a port-scan proxy for arbitrary targets
                    return self.send(400, {"error": "ip must be inside the scanned network"})
                return self.send(200, nm.probe(ip))
            self.send(404, {"error": "not found"})

        def do_POST(self):
            # JSON content-type forces a CORS preflight, so other sites can't POST here
            if not self.ok_host() or "application/json" not in (self.headers.get("Content-Type") or ""):
                return self.send(403, {"error": "forbidden"})
            try:
                body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 65536)) or b"{}")
            except ValueError:
                return self.send(400, {"error": "bad json"})
            if self.path == "/api/scan":
                nm.wake.set()
                return self.send(202, {"ok": True})
            if self.path == "/api/device":
                with nm.lock:
                    d = nm.devices.get(body.get("ip"))
                    if not d:
                        return self.send(404, {"error": "unknown device"})
                    for k, n in (("label", 100), ("notes", 2000)):
                        if isinstance(body.get(k), str):
                            d[k] = body[k][:n]
                    nm.save()
                return self.send(200, d)
            self.send(404, {"error": "not found"})
    return H


# ---------- CLI ----------

def print_table(s):
    m = s["meta"]
    print(f"{m['iface']}  {m['ip']}  net {m['cidr']}  gw {m['gateway']}\n")
    print(f"{'IP':<16}{'STATUS':<8}{'MAC':<19}{'TYPE':<10}{'RTT':>7}  {'HOST / VENDOR':<40}PORTS")
    for d in s["devices"]:
        rtt = f"{d['rtt']:.1f}" if d.get("rtt") is not None else "-"
        name = d.get("label") or d.get("hostname") or d.get("vendor") or ""
        print(f"{d['ip']:<16}{d['status']:<8}{d.get('mac') or '-':<19}{d.get('type', ''):<10}{rtt:>7}  "
              f"{name[:39]:<40}{','.join(map(str, d.get('ports') or []))}")
    if m.get("error"):
        print(f"\n[error] {m['error']}")
    for e in s["events"]:
        if e["level"] != "info":
            print(f"\n[{e['level']}] {e['msg']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("serve", "scan"):
        p = sub.add_parser(name)
        p.add_argument("--iface", help="interface (default: the one with the default route)")
        p.add_argument("--cidr", help="network to scan (default: interface subnet, max 4096 addrs)")
        p.add_argument("--no-ports", action="store_true", help="skip TCP port scan")
        p.add_argument("--no-traceroute", dest="traceroute", action="store_false", help="skip upstream path discovery")
        p.add_argument("--interval", type=int, default=60, help="seconds between full scans (serve)")
        if name == "serve":
            p.add_argument("--bind", default="127.0.0.1")
            p.add_argument("--port", type=int, default=8765)
        else:
            p.add_argument("--json", action="store_true")
    sub.add_parser("update-oui", help=f"download vendor DB from {OUI_URL}")
    a = ap.parse_args()

    if a.cmd == "update-oui":
        DATA.mkdir(parents=True, exist_ok=True)
        req = urllib.request.Request(OUI_URL, headers={"User-Agent": "Mozilla/5.0 netmap"})
        with urllib.request.urlopen(req, timeout=60) as r:
            (DATA / "oui.txt").write_bytes(r.read())
        return print(f"saved {DATA / 'oui.txt'}")

    nm = Netmap(a)
    if a.cmd == "scan":
        nm.scan()
        s = nm.snapshot()
        return print(json.dumps(s, indent=2)) if a.json else print_table(s)

    loopback = ipaddress.ip_address(a.bind).is_loopback
    if not loopback:
        print(f"WARNING: bound to {a.bind} — anyone who can reach it can see your inventory and trigger scans.")
    nm.loops()
    srv = ThreadingHTTPServer((a.bind, a.port), make_handler(nm, loopback))
    print(f"netmap UI: http://{'127.0.0.1' if loopback else a.bind}:{a.port}   (Ctrl-C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
