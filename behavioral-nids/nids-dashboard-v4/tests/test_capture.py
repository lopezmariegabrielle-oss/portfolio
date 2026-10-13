import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.capture import FlowTable, is_noise, parse_line  # noqa: E402

TCP = "1700000000.100000 IP 192.168.1.20.54321 > 142.250.74.46.443: Flags [{}], seq 1, win 10, length {}"
REPLY = "1700000000.200000 IP 142.250.74.46.443 > 192.168.1.20.54321: Flags [{}], seq 1, win 10, length {}"


def test_parse_tcp_udp_icmp_ipv6():
    p = parse_line(TCP.format("S", 0))
    assert (p["src"], p["sport"], p["dst"], p["dport"], p["proto"], p["flags"]) == \
        ("192.168.1.20", 54321, "142.250.74.46", 443, "TCP", "S")
    assert parse_line("1700000000.1 IP 10.0.0.1.5000 > 8.8.8.8.53: UDP, length 40")["proto"] == "UDP"
    icmp = parse_line("1700000000.1 IP 10.0.0.1 > 10.0.0.2: ICMP echo request, id 1, seq 1, length 64")
    assert icmp["proto"] == "ICMP" and icmp["dport"] is None
    v6 = parse_line("1700000000.1 IP6 2a01:cb00::1.443 > 2a01:cb00::2.50000: Flags [P.], length 19")
    assert v6["src"] == "2a01:cb00::1" and v6["dport"] == 50000


@pytest.mark.parametrize("bad", [
    "", "garbage; rm -rf /", "1700000000.1 ARP, Request who-has 1.1.1.1 tell 2.2.2.2, length 28",
    "1700000000.1 IP evil.<script> > b.c: Flags [S], length 0",
    "1700000000.1 IP 1.2.3.4.99999 > 5.6.7.8.80: Flags [S], length 0",
])
def test_parse_rejects_bad_input(bad):
    assert parse_line(bad) is None


def test_noise_filter():
    assert is_noise("224.0.0.251") and is_noise("255.255.255.255") and not is_noise("142.250.74.46")


def test_flow_assembly_both_directions():
    t = FlowTable()
    for line in (TCP.format("S", 0), REPLY.format("S.", 0), TCP.format("P.", 500), REPLY.format("P.", 1200),
                 REPLY.format("F.", 0)):
        t.add(parse_line(line))
    assert len(t.flows) == 1
    assert t.expire(1700000000.3) == []          # encore dans le delai de grace
    (f,) = t.expire(1700000010.0)
    assert f["src_bytes"] == 500 and f["dst_bytes"] == 1200 and f["packets"] == 5 and f["failed"] == 0


def test_unanswered_syn_is_failed_and_port_scan_indicators():
    t = FlowTable()
    for port in range(1, 51):
        t.add({"ts": 1700000000.0 + port * 0.01, "src": "203.0.113.7", "dst": "192.168.1.20", "sport": 40000,
               "dport": port, "proto": "TCP", "size": 0, "flags": "S"})
    flows = t.expire(1700000100.0)
    assert len(flows) == 50 and all(f["failed"] == 1 for f in flows)
    assert max(f["distinct_ports"] for f in flows) == 50 and max(f["conn_rate"] for f in flows) == 50
