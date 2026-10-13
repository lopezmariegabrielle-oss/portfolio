"""Generateur de flux reseau SIMULES (normaux + attaques) pour entrainer et tester le modele.

Chaque flux est un dict avec des caracteristiques de COMPORTEMENT :
  duration (s), src_bytes, dst_bytes, packets, dst_port, proto,
  failed (1 = connexion refusee), conn_rate (connexions/min de la source),
  distinct_ports (ports differents contactes par la source sur la derniere minute).
Les IPs utilisent les plages reservees a la documentation (RFC 5737) et le reseau prive.
"""
import numpy as np

INTERNAL = ["192.168.1.%d" % i for i in (10, 24, 31, 42, 57, 88)]
EXTERNAL = ["203.0.113.%d" % i for i in (7, 23, 58, 101, 166)] + ["198.51.100.%d" % i for i in (14, 77, 203)]
COMMON_PORTS = [443, 443, 443, 80, 53, 22, 123, 993]
PROTO_OF = {443: "TCP", 80: "TCP", 53: "UDP", 22: "TCP", 123: "UDP", 993: "TCP"}


def _ips(rng, n, pool):
    return rng.choice(pool, n)


def normal_flows(n, rng):
    ports = rng.choice(COMMON_PORTS, n)
    out = []
    for p, s, d in zip(ports, _ips(rng, n, INTERNAL), _ips(rng, n, EXTERNAL)):
        out.append({
            "src_ip": s, "dst_ip": d, "dst_port": int(p), "proto": PROTO_OF[int(p)],
            "duration": float(rng.lognormal(0.5, 1.0)),
            "src_bytes": float(rng.lognormal(6.5, 1.2)),
            "dst_bytes": float(rng.lognormal(8.0, 1.5)),
            "packets": float(1 + rng.poisson(12)),
            "failed": int(rng.random() < 0.01),
            "conn_rate": float(1 + rng.poisson(6)),
            "distinct_ports": float(1 + rng.poisson(1.5)),
            "label": "normal",
        })
    return out


def attack_flows(n, rng, kind=None):
    kinds = ["portscan", "bruteforce_ssh", "exfiltration"]
    out = []
    for _ in range(n):
        k = kind or rng.choice(kinds)
        src, dst = rng.choice(EXTERNAL if rng.random() < 0.7 else INTERNAL), rng.choice(INTERNAL)
        if k == "portscan":
            f = dict(dst_port=int(rng.integers(1, 65535)), proto="TCP", duration=float(rng.uniform(0.001, 0.05)),
                     src_bytes=float(rng.uniform(40, 80)), dst_bytes=float(rng.uniform(0, 60)),
                     packets=float(rng.integers(1, 3)), failed=int(rng.random() < 0.9),
                     conn_rate=float(rng.uniform(80, 400)), distinct_ports=float(rng.uniform(40, 300)))
        elif k == "bruteforce_ssh":
            f = dict(dst_port=22, proto="TCP", duration=float(rng.uniform(0.2, 2.0)),
                     src_bytes=float(rng.uniform(300, 900)), dst_bytes=float(rng.uniform(200, 600)),
                     packets=float(rng.integers(8, 20)), failed=int(rng.random() < 0.85),
                     conn_rate=float(rng.uniform(40, 150)), distinct_ports=1.0)
        else:  # exfiltration
            f = dict(dst_port=int(rng.choice([443, 53])), proto="TCP", duration=float(rng.uniform(60, 600)),
                     src_bytes=float(rng.lognormal(14.5, 0.6)), dst_bytes=float(rng.uniform(200, 2000)),
                     packets=float(rng.integers(2000, 20000)), failed=0,
                     conn_rate=float(rng.uniform(1, 5)), distinct_ports=1.0)
        f.update(src_ip=str(src), dst_ip=str(dst), label=str(k))
        out.append(f)
    return out
