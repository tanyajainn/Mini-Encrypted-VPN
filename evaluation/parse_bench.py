#!/usr/bin/env python3
"""Parse actual iperf3 JSON + ping observations. Reject failed/incomplete runs."""
import csv
import json
import re
import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('Usage: python3 evaluation/parse_bench.py RESULTS/raw')
raw = Path(sys.argv[1])
w = csv.writer(sys.stdout)
w.writerow(['condition', 'path', 'repeat', 'tcp_mbps_received',
            'tcp_retransmits', 'udp_mbps_received', 'udp_loss_percent',
            'udp_out_of_order', 'ping_avg_ms', 'ping_loss_percent'])
found = False
for tcp_path in sorted(raw.glob('*.tcp.json')):
    found = True
    label = tcp_path.name.removesuffix('.tcp.json')
    condition, path, repeat = label.rsplit('-', 2)
    tcp = json.loads(tcp_path.read_text(encoding='utf-8'))
    udp = json.loads((raw / (label + '.udp.json')).read_text(encoding='utf-8'))
    for kind, report in [('TCP', tcp), ('UDP', udp)]:
        if report.get('error') or not report.get('end'):
            raise SystemExit(f'{label}: {kind} iperf3 failed/incomplete: {report.get("error", "missing end statistics")}')
    ping = (raw / (label + '.ping.txt')).read_text(encoding='utf-8')
    rtt = re.search(r'(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = [\d.]+/([\d.]+)', ping)
    loss = re.search(r'([\d.]+)% packet loss', ping)
    end_tcp, end_udp = tcp['end'], udp['end']
    t_recv = end_tcp.get('sum_received') or {}
    t_sent = end_tcp.get('sum_sent') or {}
    u_sum = end_udp.get('sum') or end_udp.get('sum_received') or {}
    if 'bits_per_second' not in t_recv or 'bits_per_second' not in u_sum:
        raise SystemExit(f'{label}: missing received throughput; refusing to report zeros')
    if 'lost_percent' not in u_sum:
        raise SystemExit(f'{label}: UDP loss summary missing')
    w.writerow([condition, path, repeat,
                round(t_recv['bits_per_second'] / 1e6, 3),
                t_sent.get('retransmits', ''),
                round(u_sum['bits_per_second'] / 1e6, 3),
                u_sum['lost_percent'], u_sum.get('out_of_order', ''),
                rtt.group(1) if rtt else '', loss.group(1) if loss else ''])
if not found:
    raise SystemExit(f'No iperf3 JSON measurements in {raw}')
