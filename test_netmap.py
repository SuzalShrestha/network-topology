"""Run: python3 test_netmap.py  — parser checks against real macOS/Linux output samples."""
import netmap as n

assert n.parse_arp("""? (192.168.1.64) at 0:22:6d:8b:de:83 on en0 ifscope [ethernet]
? (192.168.1.5) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]""") == {"192.168.1.64": "00:22:6d:8b:de:83"}
assert n.parse_arp("""192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
192.168.1.9 dev eth0 lladdr aa:bb:cc:dd:ee:00 FAILED
192.168.1.7 dev eth0  FAILED""") == {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}

assert n.parse_ping("64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.345 ms") == 12.345
assert n.parse_ping("Request timeout for icmp_seq 0") is None

assert n.parse_lsof("""COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
Google\\x20C 812 me   23u  IPv4 0x1      0t0  TCP 192.168.1.70:52311->142.250.1.1:443 (ESTABLISHED)
ssh      900 me    3u  IPv6 0x2      0t0  TCP [fe80::1]:5000->[2606:4700::1]:22 (ESTABLISHED)""") == [
    {"proc": "Google C", "pid": 812, "local": "192.168.1.70", "lport": 52311, "remote": "142.250.1.1", "rport": 443},
    {"proc": "ssh", "pid": 900, "local": "fe80::1", "lport": 5000, "remote": "2606:4700::1", "rport": 22}]

assert n.parse_ss('0 0 10.0.0.5:52311 [::ffff:1.2.3.4]:443 users:(("firefox",pid=12,fd=3))') == [
    {"proc": "firefox", "pid": 12, "local": "10.0.0.5", "lport": 52311, "remote": "1.2.3.4", "rport": 443}]

assert n.parse_traceroute("""traceroute to 1.1.1.1 (1.1.1.1), 12 hops max, 40 byte packets
 1  192.168.1.254  2.9 ms
 2  *
 3  10.1.1.1  8.12 ms""") == [{"hop": 1, "ip": "192.168.1.254", "rtt": 2.9}, {"hop": 2, "ip": None, "rtt": None},
                             {"hop": 3, "ip": "10.1.1.1", "rtt": 8.12}]

assert n.parse_iface_bytes("""Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
en0   1500  <Link#14>   96:ad:06:04:ac:be  100     0       5000      200     0       7000     0
en0   1500  192.168.1     192.168.1.70     100     -       5000      200     -       7000     -""", "en0", mac_os=True) == (5000, 7000)
assert n.parse_iface_bytes("""Inter-|   Receive                                                |  Transmit
  eth0: 1234 10 0 0 0 0 0 0 5678 20 0 0 0 0 0 0""", "eth0", mac_os=False) == (1234, 5678)

assert n.guess_type({"ports": [9100]}) == "printer"
assert n.guess_type({"is_gateway": True, "ports": [9100]}) == "router"
assert n.vendor("02:11:22:33:44:55") == "Private (randomized MAC)"
print("ok")
