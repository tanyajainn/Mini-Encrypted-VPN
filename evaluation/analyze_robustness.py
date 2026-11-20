#!/usr/bin/env python3
"""Pure-stdlib aggregation with 95% bootstrap CI and conservative policy gate.

Input model is synthetic post-authentication packet arrivals, NOT a real network
trace. Report out-of-window false drops separately from replay rejection.
"""
import csv
import random
import sys
from collections import defaultdict
from pathlib import Path

if len(sys.argv) not in (2, 3):
    raise SystemExit('usage: analyze_robustness.py replay-robustness.csv [summary.csv]')
source = Path(sys.argv[1])
out = Path(sys.argv[2]) if len(sys.argv) == 3 else source.with_name('replay-robustness-summary.csv')
groups = defaultdict(list)
with source.open(newline='') as f:
    for r in csv.DictReader(f):
        for field in ('accepted_immediate_duplicates', 'accepted_end_replays'):
            if int(r[field]) != 0:
                raise ValueError('replay experiment accepted a duplicate: ' + str(r))
        key = (r['profile'], int(r['max_delay_ticks']), int(r['window']))
        groups[key].append(100 * int(r['late_originals']) / int(r['originals']))

with out.open('w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(('profile', 'max_delay_ticks', 'window', 'runs', 'mean_drop_percent',
                     'bootstrap_95pct_low', 'bootstrap_95pct_high', 'worst_seed_drop_percent',
                     'bitmap_bytes', 'replay_state_bytes'))
    for profile, cap, window in sorted(groups):
        values = groups[(profile, cap, window)]
        assert len(values) == 20, 'expected exactly 20 seeds per configuration'
        rng = random.Random(20261120 + cap + window)
        bootstrap = sorted(sum(rng.choices(values, k=len(values)))/len(values) for _ in range(2000))
        writer.writerow((profile, cap, window, len(values), round(sum(values)/len(values), 4),
                         round(bootstrap[49], 4), round(bootstrap[1949], 4),
                         round(max(values), 4), (window + 7)//8, (window + 7)//8 + 8))
print(f'Wrote {out} ({len(groups)} profiles/configurations)')
print('Minimum window passing <=1% worst-seed false drops for every model at max delay 256:')
for window in (32,64,128,256,512):
    worst = max(groups[(model, 256, window)][i] for model in ('uniform','normal','bursty','alternating') for i in range(20))
    print(f'  {window:>3} packets: worst-seed={worst:.3f}%  bitmap={(window+7)//8}B')
    if worst <= 1:
        print('  FIRST WINDOW THAT PASSES this synthetic criterion')
        break
