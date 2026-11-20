#!/usr/bin/env python3
"""Summarize repeat medians, directly measured ratios and RTT overhead."""
import csv
import statistics as stats
import sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit('Usage: python3 evaluation/summarize_bench.py summary.csv')
path = Path(sys.argv[1])
with path.open(newline='', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))
if not rows:
    raise SystemExit('Empty benchmark file')
metrics = ['tcp_mbps_received', 'tcp_retransmits', 'udp_mbps_received',
           'udp_loss_percent', 'udp_out_of_order', 'ping_avg_ms', 'ping_loss_percent']
group = defaultdict(lambda: defaultdict(list))
for row in rows:
    for m in metrics:
        if row[m] != '':
            group[(row['condition'], row['path'])][m].append(float(row[m]))
median = {k: {m: stats.median(vals) for m, vals in data.items()}
          for k, data in group.items()}
writer = csv.writer(sys.stdout)
writer.writerow(['condition', 'path', 'runs', 'median_tcp_mbps',
                 'tcp_ratio_to_direct', 'median_udp_mbps', 'median_udp_loss_percent',
                 'median_udp_out_of_order', 'median_ping_avg_ms', 'rtt_extra_ms',
                 'median_ping_loss_percent'])
for (condition, route), data in sorted(median.items()):
    direct = median.get((condition, 'direct'), {})
    def val(metric):
        return round(data[metric], 3) if metric in data else ''
    t = data.get('tcp_mbps_received')
    base = direct.get('tcp_mbps_received')
    ratio = round(t / base, 3) if t is not None and base else ''
    p = data.get('ping_avg_ms')
    dp = direct.get('ping_avg_ms')
    delta = round(p - dp, 3) if p is not None and dp is not None else ''
    writer.writerow([condition, route, len(group[(condition, route)]['tcp_mbps_received']),
                     val('tcp_mbps_received'), ratio, val('udp_mbps_received'),
                     val('udp_loss_percent'), val('udp_out_of_order'),
                     val('ping_avg_ms'), delta, val('ping_loss_percent')])
