#!/usr/bin/env python3
"""Plot the fixed max_delay=256 experiment; keeps separate model traces."""
import csv
import sys
from pathlib import Path
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
except ImportError as e:
    raise SystemExit('pip install matplotlib to render the optional plot') from e

if len(sys.argv) not in (2,3):
    raise SystemExit('usage: plot_robustness.py summary.csv [plot.png]')
src = Path(sys.argv[1]); out = Path(sys.argv[2]) if len(sys.argv)==3 else src.with_suffix('.png')
by_model={}
with src.open(newline='') as f:
    for r in csv.DictReader(f):
        if int(r['max_delay_ticks']) != 256: continue
        by_model.setdefault(r['profile'], []).append((int(r['window']),float(r['mean_drop_percent'])))
fig,ax=plt.subplots(figsize=(9,5.25))
for model, records in sorted(by_model.items()):
    xx,yy=zip(*sorted(records))
    ax.plot(xx, yy, '-o', label=model)
ax.axhline(1.0, color='gray', linestyle='--', linewidth=1, label='1% target')
ax.set_xlabel('Replay bitmap window (packets)')
ax.set_ylabel('Legitimate original packets rejected (%)')
ax.set_title('Synthetic delay model sensitivity: 256-tick maximum, 20 seeded traces')
ax.grid(alpha=.2)
ax.legend()
fig.tight_layout()
fig.savefig(out, dpi=180)
print(f'Wrote {out}')
