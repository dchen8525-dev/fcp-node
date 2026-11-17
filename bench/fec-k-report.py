#!/usr/bin/env python3
"""Summarise one bench/fec-k-ab.sh run directory.

Every leg is a 10-minute download; each whole-body GET is its own session and
therefore its own trace file, so per-file counters are read at their last row
and summed across the leg. k is reported as the row-weighted distribution
(each stream row is 2 s of the sender's life), which is what the parity
overhead actually was, not what the controller intended.
"""
import json
import sys
from collections import Counter
from pathlib import Path
from statistics import median


def rows(path):
    out = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def leg_stats(leg_dir: Path):
    stats = {"k": Counter(), "loss": [], "srtt": [], "retx": 0, "sent": 0,
             "rows": 0, "files": 0, "sendBw": []}
    for path in sorted(leg_dir.glob("*server*.jsonl")):
        rs = [r for r in rows(path) if r.get("t") == "stream"]
        if not rs:
            continue
        stats["files"] += 1
        stats["rows"] += len(rs)
        # Peak, not last: the counters live on the Stream object, so a sample
        # taken after the stream closed reads 0/0. The peak is the run's total
        # because one GET = one session = one data stream.
        stats["retx"] += max(r.get("retx", 0) for r in rs)
        stats["sent"] += max(r.get("sent", 0) for r in rs)
        for r in rs:
            if "k" in r:
                stats["k"][r["k"]] += 1
            if "loss" in r:
                stats["loss"].append(r["loss"])
            if "srtt" in r:
                stats["srtt"].append(r["srtt"])
            if "sendBw" in r:
                stats["sendBw"].append(r["sendBw"])
    return stats


def main(run_dir: str) -> None:
    root = Path(run_dir)
    legs = {}
    if (root / "legs.txt").exists():
        for line in (root / "legs.txt").read_text().splitlines():
            tokens = line.split()
            if not tokens:
                continue
            parts = dict(p.split("=", 1) for p in tokens[1:] if "=" in p)
            parts["leg"] = tokens[0].replace("leg", "")
            legs[parts["leg"]] = parts
    print(f"{'leg':4} {'pin':>3} {'goodput':>9} {'est wire':>9} {'k(mean)':>8} {'k dist':<22} "
          f"{'loss':>6} {'srtt':>5} {'retx/sent':>14} {'retx%':>6}")
    for name in sorted(legs, key=lambda s: int("".join(ch for ch in s if ch.isdigit()) or 0)):
        info = legs[name]
        d = root / f"leg{name}"
        s = leg_stats(d) if d.exists() else None
        if not s or not s["rows"]:
            print(f"{name:4} {info.get('pin','?'):>3} {'no server trace':>9}")
            continue
        total = sum(s["k"].values())
        kmean = sum(k * n for k, n in s["k"].items()) / total
        dist = " ".join(f"k{k}:{100*n/total:.0f}%" for k, n in sorted(s["k"].items()))
        loss = median(s["loss"]) if s["loss"] else 0
        srtt = median(s["srtt"]) if s["srtt"] else 0
        retx, sent = s["retx"], s["sent"]
        rate = 100.0 * retx / sent if sent else 0.0
        bps = int(info.get("Bps", 0))
        # Goodput x (1 + k/d) is what the wire had to carry for it: if this is
        # flat across legs the path was the binding constraint and extra parity
        # is pure tax; if it rises with k, parity was buying back real capacity.
        wire = bps * (1 + kmean / 10.0)
        print(f"{name:4} {info.get('pin','?'):>3} {bps/1048576:>8.2f}M {wire/1048576:>8.2f}M "
              f"{kmean:>8.2f} {dist:<22} {loss*100:>5.1f}% {srtt:>4.0f}m "
              f"{retx:>7}/{sent:<7} {rate:>5.1f}%")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
