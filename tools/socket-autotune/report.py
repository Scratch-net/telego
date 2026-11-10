#!/usr/bin/env python3
"""Summarize paired socket-policy runs without mixing pilots into the results."""

import argparse
import base64
from collections import Counter, defaultdict
import csv
import html
import json
import os
from pathlib import Path
from statistics import median


def summarize(paths):
    runs = []
    environments = []
    keys = set()
    for path in paths:
        environments.append(json.loads((path / "environment.json").read_text()))
        for file in sorted(path.glob("*/result.json")):
            row = json.loads(file.read_text())
            error_record = file.parent / "client.error"
            if row["status"] != "pass" and error_record.exists():
                try:
                    row["client_observed_error"] = json.loads(error_record.read_text())[
                        "error"
                    ]
                except (ValueError, KeyError):
                    row["client_error_record_status"] = "Incomplete error record"
            key = (
                row["scenario"]["name"],
                row["direction"],
                row["streams"],
                row["repeat"],
                row["mode"],
            )
            if row["status"] == "pass" and key in keys:
                raise ValueError("Duplicate case: " + repr(key))
            if row["status"] == "pass":
                keys.add(key)
            row["artifact"] = str(file.resolve())
            runs.append(row)
    hashes = {json.dumps(e["binary_sha256"], sort_keys=True) for e in environments}
    if len(hashes) != 1:
        raise ValueError("Input directories contain different executable hashes")
    groups = defaultdict(dict)
    attempts = defaultdict(Counter)
    failures_by_case = defaultdict(Counter)
    for row in runs:
        key = (row["scenario"]["name"], row["direction"], row["streams"])
        values = groups[key]
        attempts[key][row["mode"]] += 1
        if row["status"] == "pass":
            values[(row["repeat"], row["mode"])] = row
        else:
            failures_by_case[key][row["mode"]] += 1
    cases = []
    for (scenario, direction, streams), values in sorted(groups.items()):
        repeats = sorted(
            {
                r
                for r, mode in values
                if (r, "auto") in values and (r, "fixed") in values
            }
        )
        for repeat in repeats:
            if (
                values[(repeat, "auto")]["bytes_requested"]
                != values[(repeat, "fixed")]["bytes_requested"]
            ):
                raise ValueError(
                    "Paired payload sizes differ: "
                    + repr((scenario, direction, streams, repeat))
                )
        ratios = [
            values[(r, "auto")]["transfer"]["MiB_s"]
            / values[(r, "fixed")]["transfer"]["MiB_s"]
            for r in repeats
        ]
        case = {
            "scenario": scenario,
            "direction": direction,
            "streams": streams,
            "pairs": len(repeats),
            "paired_ratio_median": median(ratios) if ratios else None,
            "paired_ratio_min": min(ratios) if ratios else None,
            "paired_ratio_max": max(ratios) if ratios else None,
        }
        for mode in ("fixed", "auto"):
            key = (scenario, direction, streams)
            case[mode + "_attempts"] = attempts[key][mode]
            case[mode + "_failures"] = failures_by_case[key][mode]
            data = [values[(r, mode)] for r in repeats]
            if not data:
                continue
            throughput = [d["transfer"]["MiB_s"] for d in data]
            case[mode] = {
                "MiB_s_median": median(throughput),
                "MiB_s_min": min(throughput),
                "MiB_s_max": max(throughput),
                "relay_cpu_seconds_per_GiB": median(
                    d["relay_cpu_seconds_per_GiB"] for d in data
                ),
                "relay_cpu_percent_one_core": median(
                    d["relay_cpu_percent_one_core"] for d in data
                ),
                "client_cpu_seconds_per_GiB": median(
                    d["client_cpu_seconds_per_GiB"] for d in data
                ),
                "peak_rss_MiB_median": median(d["relay_peak_rss_MiB"] for d in data),
                "peak_DC_skb_MiB_median": median(
                    d["peak_DC_skb_memory_bytes_sampled"] / 1048576 for d in data
                ),
                "max_socket_sndbuf_MiB": max(
                    (
                        f.get("sndbuf", 0) / 1048576
                        for d in data
                        for f in d["relay_DC_sockets"]
                    ),
                    default=0,
                ),
                "max_socket_rcvbuf_MiB": max(
                    (
                        f.get("rcvbuf", 0) / 1048576
                        for d in data
                        for f in d["relay_DC_sockets"]
                    ),
                    default=0,
                ),
                "retransmitted_bytes_observed": sum(
                    f.get("retrans", 0) for d in data for f in d["relay_DC_sockets"]
                ),
                "retryable_http_responses": sum(
                    d["transfer"].get("retryable_http_responses", 0) for d in data
                ),
                "rtt_ms_max_observed": max(
                    (f.get("rtt", 0) for d in data for f in d["relay_DC_sockets"]),
                    default=0,
                ),
            }
        cases.append(case)
    failures = [r for r in runs if r["status"] != "pass"]
    return {
        "runs": len(runs),
        "passed": len(runs) - len(failures),
        "failures": failures,
        "cases": cases,
        "environments": environments,
        "verified_bytes": sum(
            r["transfer"]["bytes"] for r in runs if r["status"] == "pass"
        ),
    }


def plot(cases, output):
    os.environ.setdefault("MPLCONFIGDIR", str(output / ".matplotlib"))
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    profiles = ["short-100", "short-1000", "wan-1000", "long-1000", "lossy-1000"]
    labels = [
        "20 ms\n100 Mb/s",
        "20 ms\n1 Gb/s",
        "80 ms\n1 Gb/s",
        "160 ms\n1 Gb/s",
        "80 ms + 0.1% loss\n1 Gb/s",
    ]
    fig, axes = plt.subplots(2, 2, figsize=(13, 8), layout="constrained")
    for ax, (direction, streams) in zip(
        axes.flat, [("upload", 1), ("upload", 8), ("download", 1), ("download", 8)]
    ):
        subset = {
            c["scenario"]: c
            for c in cases
            if c["direction"] == direction and c["streams"] == streams
        }
        for x, profile in enumerate(profiles):
            if profile in subset and subset[profile]["pairs"] == 0:
                ax.text(
                    x,
                    0.02,
                    "no pair",
                    ha="center",
                    fontsize=8,
                    transform=ax.get_xaxis_transform(),
                )
        for mode, offset, color, title in [
            ("fixed", -0.18, "#64748b", "Fixed 512 KiB requests"),
            ("auto", 0.18, "#087f8c", "Kernel autotuning"),
        ]:
            for x, profile in enumerate(profiles):
                if profile not in subset or mode not in subset[profile]:
                    continue
                c = subset[profile][mode]
                y = c["MiB_s_median"]
                ax.bar(
                    x + offset, y, 0.34, color=color, label=title if x == 0 else None
                )
                ax.errorbar(
                    x + offset,
                    y,
                    yerr=[[y - c["MiB_s_min"]], [c["MiB_s_max"] - y]],
                    color="#172033",
                    capsize=3,
                    lw=1,
                )
        ax.set_title(
            f"{direction.title()} · {streams} stream{'s' if streams > 1 else ''}"
        )
        ax.set_xticks(range(5), labels, fontsize=8)
        ax.set_ylabel("Verified payload MiB/s")
        ax.grid(axis="y", alpha=0.2)
        ax.set_axisbelow(True)
    axes[0, 0].legend(fontsize=8)
    counts = [c["pairs"] for c in cases if c["pairs"]]
    count = (
        str(min(counts))
        if counts and min(counts) == max(counts)
        else f"{min(counts)}–{max(counts)}" if counts else "0"
    )
    fig.suptitle(
        f"Telego native WEB: fixed socket buffers vs Linux autotuning\nMedians and full observed ranges; {count} alternating pairs per case",
        fontsize=14,
    )
    fig.savefig(
        output / "throughput.png", dpi=170, bbox_inches="tight", pad_inches=0.15
    )
    fig.savefig(output / "throughput.svg", bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--notes",
        type=Path,
        help="Plain-text experiment notes to include in the report",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    summary = summarize(args.inputs)
    if args.notes:
        summary["notes"] = args.notes.read_text()
    (output / "summary.json").write_text(json.dumps(summary, indent=2))
    fields = [
        "scenario",
        "direction",
        "streams",
        "pairs",
        "fixed_attempts",
        "fixed_failures",
        "auto_attempts",
        "auto_failures",
        "paired_ratio_median",
        "paired_ratio_min",
        "paired_ratio_max",
    ]
    flat = []
    for case in summary["cases"]:
        row = {k: case[k] for k in fields}
        for mode in ("fixed", "auto"):
            row.update({mode + "_" + k: v for k, v in case.get(mode, {}).items()})
        flat.append(row)
    with (output / "cases.csv").open("w", newline="") as stream:
        columns = list(dict.fromkeys(k for row in flat for k in row))
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows(flat)
    chart = plot(summary["cases"], output)
    rows = []
    for c in summary["cases"]:
        cells = [
            c["scenario"],
            c["direction"],
            str(c["streams"]),
            str(c["pairs"]),
            f'{c["fixed_failures"]}/{c["fixed_attempts"]} · {c["auto_failures"]}/{c["auto_attempts"]}',
        ]
        if c["pairs"]:
            a, f = c["auto"], c["fixed"]
            cells += [
                f'{f["MiB_s_median"]:.2f}',
                f'{a["MiB_s_median"]:.2f}',
                f'{c["paired_ratio_median"]:.2f}× ({c["paired_ratio_min"]:.2f}–{c["paired_ratio_max"]:.2f})',
                f'{f["relay_cpu_seconds_per_GiB"]:.1f} / {a["relay_cpu_seconds_per_GiB"]:.1f}',
                f'{f["peak_rss_MiB_median"]:.1f} / {a["peak_rss_MiB_median"]:.1f}',
                f'{f["peak_DC_skb_MiB_median"]:.2f} / {a["peak_DC_skb_MiB_median"]:.2f}',
                f'{f["retryable_http_responses"]} / {a["retryable_http_responses"]}',
            ]
        else:
            cells += ["n/a"] * 7
        rows.append(
            "<tr>"
            + "".join("<td>" + html.escape(cell) + "</td>" for cell in cells)
            + "</tr>"
        )
    heads = [
        "Network",
        "Direction",
        "Streams",
        "Pairs",
        "Failures/attempts: fixed · auto",
        "Fixed MiB/s",
        "Auto MiB/s",
        "Paired auto/fixed: median (range)",
        "CPU s/GiB: fixed / auto",
        "Peak RSS MiB: fixed / auto",
        "Peak DC socket memory MiB: fixed / auto",
        "HTTP retries: fixed / auto",
    ]
    document = """<!doctype html><meta charset="utf-8"><title>Telego socket autotuning experiment</title>
<style>body{font:16px/1.5 system-ui;margin:32px auto;max-width:1450px;padding:0 24px;color:#172033}h1{font-size:30px}table{border-collapse:collapse;font-size:13px;width:100%}td,th{padding:9px;border-bottom:1px solid #dbe1e7;text-align:right}td:first-child,th:first-child{text-align:left}th{background:#eef4f7}img{max-width:100%}pre{overflow:auto;background:#eef4f7;padding:16px}.scroll{overflow:auto}li{margin:7px 0}</style>
<h1>Telego socket autotuning experiment</h1>"""
    document += f'<p>{summary["passed"]}/{summary["runs"]} recorded runs passed. Verified payload: {summary["verified_bytes"]/1073741824:.2f} GiB, excluding warmup.</p>'
    if args.notes:
        document += "<p>" + html.escape(summary["notes"]).replace("\n", "<br>") + "</p>"
    if chart:
        png = base64.b64encode((output / "throughput.png").read_bytes()).decode("ascii")
        document += (
            '<img src="data:image/png;base64,'
            + png
            + '" alt="Fixed and autotuned throughput across five network profiles">'
        )
    document += (
        """<p>Fixed requests 512 KiB for SO_SNDBUF and SO_RCVBUF. Linux reports doubled buffer limits for these requests.
Auto leaves both limits under kernel control. The executable source and build flags otherwise match.</p>
<p>Throughput uses only pairs where both transfers passed. Failures appear separately for every case, including cases with no completed pair.
Performance among successful pairs does not establish reliability.</p>
<div class="scroll"><table><tr>"""
        + "".join("<th>" + h + "</th>" for h in heads)
        + "</tr>"
        + "".join(rows)
        + "</table></div>"
    )
    document += """<h2>Method</h2><ul>
<li>The real native HTTP WEB server, session manager, logical gproxy backend, direct DC socket, and obfuscated2 AES-CTR carry synthetic payloads.</li>
<li>Each run warms 1 MiB per stream. The default payload is 64 MiB, or 16 MiB for lossy-1000. Per-run records give the exact size.</li>
<li>The timed phase includes the payload transfer and SHA-256 acknowledgement.</li>
<li>The default matrix uses six paired runs per case. Each table row gives the completed pair count. The order alternates.</li>
<li>The recorded environment gives each lab's CPU affinity. With six available CPUs, relay, peer, and client each use two distinct CPUs.</li>
<li>Each test process uses GOMAXPROCS=2.</li>
<li>A router applies half the configured RTT on each leg, plus the rate cap and loss. It has no local TCP sender.</li>
<li>All four veth interfaces disable TSO, GSO, and GRO. Endpoint namespaces disable TCP metric caching.</li>
<li>Ping records path RTT. tc records the configured rate, delay, loss, packet counts, and drops.</li>
<li>Every payload byte and SHA-256 acknowledgement must match. Session shutdown must leave zero sessions, streams, backend dials, and pending items/bytes.</li>
<li>The synthetic client honors explicit retryable HTTP responses and Retry-After. It replays the same body and upload sequence.</li>
</ul><h2>Interpretation limits</h2><ul>
<li>The recorded environment gives the host kernel and TCP limits. Kernel limits and CPU capacity can differ from production.</li>
<li>The impairment applies to the DC leg. The private native HTTP frontend has no TLS, NGINX, browser, or client WAN.</li>
<li>The peer implements the transport handshake and payload exchange. It does not implement Telegram RPCs or middle-end pooling.</li>
<li>The client uses a fixed 1 ms pause between download polls. The test does not reproduce all browser bridge scheduling.</li>
<li>The synthetic client serializes uplink requests. It does not reproduce the native client's complete carrier scheduling.</li>
<li>No loss seed is supplied. Paired loss runs use independent random draws.</li>
<li>The rate is a ceiling. Application throughput can stop below that ceiling because of CPU, TCP windows, or HTTP scheduling.</li>
<li>RSS and queued DC socket memory use 200 ms samples. These values are observed lower bounds for peaks.</li>
<li>Socket buffer values are configured budgets, not reserved allocations or strict memory bounds. The socket memory column sums receive and queued-send skb allocations.</li>
<li>CPU cost includes the timed phase and brief client cleanup. Relay CPU uses the host process accounting tick resolution.</li>
<li>Socket retransmission counters include warmup. They describe only the sampled relay DC endpoint, not the whole path.</li>
<li>HTTP retry totals include warmup. Startup retries do not automatically imply a timed throughput penalty.</li>
<li>Ranges describe the recorded observations. They are not confidence intervals or proof of production performance.</li>
<li>These finite transfers follow a 1 MiB warmup per stream. They do not establish fully converged TCP throughput.</li>
<li>Short successful transfers establish payload integrity and bounded cleanup. They do not establish long-term leak freedom.</li>
</ul><h2>Evidence and reproduction</h2>
<p><a href="summary.json">Summary JSON</a> · <a href="cases.csv">All case metrics in CSV</a> · <a href="throughput.svg">Vector chart</a></p>
<p>The input directories contain per-run results, socket samples, process logs, cleanup counters, and network configuration.</p>
<p>The build manifest records both executable hashes. The repository tools/socket-autotune directory contains the reusable runner.</p>
<h2>Method references</h2><p>
<a href="https://docs.kernel.org/networking/ip-sysctl.html">Linux TCP buffer and autotuning controls</a> ·
<a href="https://man7.org/linux/man-pages/man8/tc-netem.8.html">netem placement and timer limits</a></p>"""
    if summary["failures"]:
        document += (
            "<h2>Failed runs</h2><pre>"
            + html.escape(json.dumps(summary["failures"], indent=2))
            + "</pre>"
        )
    document += (
        "<h2>Recorded environment</h2><pre>"
        + html.escape(json.dumps(summary["environments"], indent=2))
        + "</pre>"
    )
    (output / "report.html").write_text(document)
    print(
        json.dumps(
            {
                "runs": summary["runs"],
                "passed": summary["passed"],
                "cases": len(summary["cases"]),
                "report": str(output / "report.html"),
            }
        )
    )


if __name__ == "__main__":
    main()
