#!/usr/bin/env python3
import argparse, concurrent.futures, datetime, hashlib, json, os, pathlib, random, re, signal, statistics, subprocess, sys, threading, time, traceback

ROOT = pathlib.Path(__file__).resolve().parent
BIN_ROOT = ROOT.parents[1] / ".local" / "socket-autotune"
SCENARIOS = [
    {"name": "short-100", "rtt": 20, "mbit": 100, "loss": 0},
    {"name": "short-1000", "rtt": 20, "mbit": 1000, "loss": 0},
    {"name": "wan-1000", "rtt": 80, "mbit": 1000, "loss": 0},
    {"name": "long-1000", "rtt": 160, "mbit": 1000, "loss": 0},
    {"name": "lossy-1000", "rtt": 80, "mbit": 1000, "loss": 0.1},
]
TCP_SYSCTLS = [
    "net.ipv4.tcp_rmem",
    "net.ipv4.tcp_wmem",
    "net.core.rmem_max",
    "net.core.wmem_max",
    "net.ipv4.tcp_congestion_control",
    "net.ipv4.tcp_no_metrics_save",
]


class Lab:
    def __init__(self, root, down_poll_ms=1):
        self.root = root
        self.down_poll_ms = down_poll_ms
        self.children = []
        self.apps = []

    def run(self, *args, ns=None, check=True, timeout=15):
        cmd = (["nsenter", "-t", str(ns), "-n", "--"] if ns else []) + list(args)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if check and r.returncode:
            raise RuntimeError(str(cmd) + ": " + r.stderr[-1500:])
        return r

    def ns(self):
        p = subprocess.Popen(["unshare", "-n", "sleep", "3600"])
        self.children.append(p)
        original = os.readlink("/proc/self/ns/net")
        for _ in range(100):
            if p.poll() is not None:
                raise RuntimeError("endpoint namespace creation failed")
            if os.readlink("/proc/" + str(p.pid) + "/ns/net") != original:
                break
            time.sleep(0.01)
        self.run("ip", "link", "set", "lo", "up", ns=p.pid)
        return p.pid

    def setup(self):
        self.run("ip", "link", "set", "lo", "up")
        self.p = self.ns()
        self.d = self.ns()
        for name, remote, ns, subnet in [
            ("rp", "ep", self.p, "10.74.1"),
            ("rd", "ed", self.d, "10.74.2"),
        ]:
            self.run("ip", "link", "add", name, "type", "veth", "peer", "name", remote)
            self.run("ip", "link", "set", remote, "netns", str(ns))
            self.run("ip", "addr", "add", subnet + ".1/24", "dev", name)
            self.run("ip", "link", "set", name, "up")
            self.run("ip", "addr", "add", subnet + ".2/24", "dev", remote, ns=ns)
            self.run("ip", "link", "set", remote, "up", ns=ns)
            self.run("ip", "route", "add", "default", "via", subnet + ".1", ns=ns)
            for n, dev in [(None, name), (ns, remote)]:
                self.run(
                    "ethtool", "-K", dev, "tso", "off", "gso", "off", "gro", "off", ns=n
                )
        self.run("sysctl", "-qw", "net.ipv4.ip_forward=1")
        for ns in [self.p, self.d]:
            self.run("sysctl", "-qw", "net.ipv4.tcp_no_metrics_save=1", ns=ns)

    def configure_tcp(self, values):
        for ns in [self.p, self.d]:
            for name, value in values.items():
                self.run("sysctl", "-qw", name + "=" + value, ns=ns)
                actual = self.run("sysctl", "-n", name, ns=ns).stdout
                if actual.split() != value.split():
                    raise RuntimeError("TCP setting did not take effect: " + name)

    def tcp_settings(self, ns):
        values = {}
        for name in TCP_SYSCTLS:
            result = self.run("sysctl", "-n", name, ns=ns, check=False)
            values[name] = result.stdout.strip() if result.returncode == 0 else None
        return values

    def shape(self, scenario, seed):
        for dev in ["rp", "rd"]:
            self.run("tc", "qdisc", "del", "dev", dev, "root", check=False)
            self.run(
                "tc",
                "qdisc",
                "add",
                "dev",
                dev,
                "root",
                "netem",
                "limit",
                "20000",
                "delay",
                str(scenario["rtt"] / 2) + "ms",
                "rate",
                str(scenario["mbit"]) + "mbit",
                "loss",
                "random",
                str(scenario["loss"]) + "%",
            )
        ping = self.run(
            "ping", "-n", "-c", "3", "-i", ".1", "-W", "2", "10.74.2.2", ns=self.p
        )
        m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/", ping.stdout)
        if not m:
            raise RuntimeError("RTT calibration failed: " + ping.stdout)
        return {
            "ping_min_ms": float(m[1]),
            "ping_mean_ms": float(m[2]),
            "qdisc": {
                dev: self.run("tc", "-s", "-j", "qdisc", "show", "dev", dev).stdout
                for dev in ["rp", "rd"]
            },
        }

    def wait(self, path, process, timeout=20):
        end = time.monotonic() + timeout
        while True:
            try:
                json.loads(path.read_text())
                return
            except (FileNotFoundError, json.JSONDecodeError):
                # The Go fixture publishes with WriteFile. Existence alone can
                # expose its empty or partial contents before the write ends.
                pass
            if process.poll() is not None:
                raise RuntimeError("process exited before " + path.name)
            if time.monotonic() > end:
                raise TimeoutError("waiting for " + str(path))
            time.sleep(0.01)

    def launch(self, binary, role, ns, directory, streams, direction, total):
        env = os.environ | {
            "LAB_ROLE": role,
            "LAB_DOWN_POLL_MS": str(self.down_poll_ms),
            "LAB_ROOT": str(directory),
            "LAB_STREAMS": str(streams),
            "LAB_DIRECTION": direction,
            "LAB_BYTES": str(total),
            "GOMAXPROCS": "2",
            "GOMEMLIMIT": "256MiB",
        }
        log = (directory / (role + ".log")).open("w")
        cmd = [
            "nsenter",
            "-t",
            str(ns),
            "-n",
            "--",
            str(binary),
            "-test.run=^TestSyntheticSocketPolicyHarness$",
            "-test.timeout=120s",
            "-test.count=1",
        ]
        cores = sorted(os.sched_getaffinity(0))
        assigned = (
            cores[:2]
            if role == "relay"
            else cores[2:4] if role == "peer" else cores[4:6]
        )
        cmd = (
            ["taskset", "-c", ",".join(map(str, assigned))] + cmd
            if len(cores) >= 6
            else cmd
        )
        p = subprocess.Popen(
            cmd, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
        )
        self.apps.append((p, log))
        return p

    def proc(self, pid):
        fields = (
            pathlib.Path("/proc", str(pid), "stat")
            .read_text()
            .split(") ", 1)[1]
            .split()
        )
        status = pathlib.Path("/proc", str(pid), "status").read_text()
        m = re.search(r"VmRSS:\s+(\d+)", status)
        try:
            fds = len(list(pathlib.Path("/proc", str(pid), "fd").iterdir()))
        except OSError:
            fds = None
        return {
            "ticks": int(fields[11]) + int(fields[12]),
            "rss_kib": int(m[1]) if m else 0,
            "fds": fds,
        }

    def execute(self, s, mode, streams, direction, repeat, total):
        directory = self.root / (
            s["name"]
            + "-"
            + direction
            + "-"
            + str(streams)
            + "-"
            + str(repeat)
            + "-"
            + mode
        )
        directory.mkdir(parents=True)
        result = {
            "scenario": s,
            "mode": mode,
            "streams": streams,
            "direction": direction,
            "repeat": repeat,
            "bytes_requested": total,
        }
        self.apps = []
        try:
            result["calibration"] = self.shape(s, 10000 + repeat)
            peer = self.launch(
                BIN_ROOT / "auto.test",
                "peer",
                self.d,
                directory,
                streams,
                direction,
                total,
            )
            self.wait(directory / "peer.ready", peer)
            relay = self.launch(
                BIN_ROOT / (mode + ".test"),
                "relay",
                self.p,
                directory,
                streams,
                direction,
                total,
            )
            self.wait(directory / "relay.ready", relay)
            client = self.launch(
                BIN_ROOT / "auto.test",
                "client",
                self.p,
                directory,
                streams,
                direction,
                total,
            )
            self.wait(directory / "client.warm", client, 40)
            pids = {
                k: json.loads(
                    (
                        directory / (k + ".ready" if k != "client" else "client.warm")
                    ).read_text()
                )["pid"]
                for k in ["peer", "relay", "client"]
            }
            before = {k: self.proc(pid) for k, pid in pids.items()}
            samples = []
            stop = threading.Event()

            def sample():
                with (directory / "tcp.jsonl").open("w", buffering=1) as out:
                    while not stop.is_set():
                        try:
                            raw = self.run(
                                "ss",
                                "-tinmpH",
                                "state",
                                "established",
                                ns=self.p,
                                timeout=3,
                            ).stdout
                            v = {
                                "seconds": time.monotonic(),
                                "relay": self.proc(pids["relay"]),
                                "tcp": raw,
                            }
                            samples.append(v)
                            out.write(json.dumps(v) + "\n")
                        except Exception as e:
                            out.write(json.dumps({"sample_error": str(e)}) + "\n")
                        stop.wait(0.2)

            thread = threading.Thread(target=sample)
            thread.start()
            (directory / "measure.go").touch()
            try:
                self.wait(directory / "client.result", client, 70)
            finally:
                stop.set()
                thread.join(5)
            after = {
                k: self.proc(pid)
                for k, pid in pids.items()
                if pathlib.Path("/proc", str(pid)).exists()
            }
            result["transfer"] = json.loads((directory / "client.result").read_text())
            client.wait(timeout=8)
            if client.returncode:
                raise RuntimeError(
                    "client failed: " + (directory / "client.log").read_text()[-1200:]
                )
            elapsed = result["transfer"]["seconds"]
            hz = os.sysconf("SC_CLK_TCK")
            result["client_cpu_seconds_per_GiB"] = result["transfer"][
                "client_cpu_seconds"
            ] / (total / 1073741824)
            result["cpu_seconds"] = {
                k: (after[k]["ticks"] - before[k]["ticks"]) / hz for k in after
            }
            result["relay_cpu_percent_one_core"] = (
                result["cpu_seconds"]["relay"] / elapsed * 100
            )
            result["relay_cpu_seconds_per_GiB"] = result["cpu_seconds"]["relay"] / (
                total / 1073741824
            )
            result["relay_peak_rss_MiB"] = (
                max(
                    [before["relay"]["rss_kib"]]
                    + [x["relay"]["rss_kib"] for x in samples]
                )
                / 1024
            )
            result["tcp_samples"] = len(samples)
            result["fds_before"] = before["relay"]["fds"]
            flows = {}
            peak_socket = 0
            for row in samples:
                current = None
                memory = 0
                for line in row["tcp"].splitlines():
                    if not line.startswith((" ", "\t")):
                        current = None
                        parts = line.split()
                        if (
                            "pid=" + str(pids["relay"]) + "," in line
                            and len(parts) >= 4
                            and parts[3].startswith("10.74.2.2:")
                        ):
                            current = flows.setdefault(" ".join(parts[2:4]), {})
                    elif current is not None:
                        for key, pattern in [
                            ("sndbuf", r"\btb(\d+)"),
                            ("rcvbuf", r"\brb(\d+)"),
                            ("send_alloc", r"\bw(\d+)"),
                            ("recv_alloc", r"(?<![a-z])r(\d+)"),
                            ("rtt", r"\brtt:([\d.]+)"),
                            ("retrans", r"\bbytes_retrans:(\d+)"),
                            ("sndbuf_limited", r"\bsndbuf_limited:(\d+)ms"),
                            ("rwnd_limited", r"\brwnd_limited:(\d+)ms"),
                        ]:
                            m = re.search(pattern, line)
                            if m:
                                current[key] = max(
                                    current.get(key, 0),
                                    float(m[1]) if key == "rtt" else int(m[1]),
                                )
                        sk = re.search(
                            r"skmem:\(r(\d+),rb\d+,t\d+,tb\d+,f\d+,w(\d+)", line
                        )
                        if sk:
                            memory += int(sk[1]) + int(sk[2])
                peak_socket = max(peak_socket, memory)
            result["relay_DC_sockets"] = list(flows.values())
            result["peak_DC_skb_memory_bytes_sampled"] = peak_socket
            (directory / "stop").touch()
            relay.wait(timeout=15)
            peer.wait(timeout=8)
            if relay.returncode or peer.returncode:
                raise RuntimeError("relay/peer cleanup failed")
            result["cleanup"] = json.loads((directory / "relay.closed").read_text())
            result["peer_cleanup"] = json.loads((directory / "peer.closed").read_text())
            if result["peer_cleanup"]["failed"] != 0:
                raise RuntimeError("peer detected integrity/protocol failures")
            result["qdisc_after"] = {
                dev: self.run("tc", "-s", "-j", "qdisc", "show", "dev", dev).stdout
                for dev in ["rp", "rd"]
            }
            result["status"] = "pass"
        except Exception as e:
            result["status"] = "fail"
            result["error"] = str(e)
            result["trace"] = traceback.format_exc()
        finally:
            (directory / "stop").touch()
            for p, log in self.apps:
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGTERM)
                    try:
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(p.pid, signal.SIGKILL)
                        p.wait()
                log.close()
            self.apps = []
        (directory / "result.json").write_text(json.dumps(result, indent=2))
        return result

    def close(self):
        for p in self.children:
            p.terminate()
        for p in self.children:
            p.wait(timeout=5)


def main():
    global BIN_ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument("--binaries", type=pathlib.Path, default=BIN_ROOT)
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument(
        "--continue-on-failure",
        action="store_true",
        help="Record failed cases and finish the remaining planned runs; return failure at the end",
    )
    parser.add_argument("--streams", type=int, choices=[1, 8])
    parser.add_argument("--direction", choices=["upload", "download"])
    parser.add_argument("--cpus")
    parser.add_argument(
        "--tcp-sysctls",
        type=pathlib.Path,
        help="JSON with namespace-local tcp_rmem, tcp_wmem, and tcp_congestion_control overrides",
    )
    parser.add_argument("--repeats", type=int, default=6)
    parser.add_argument(
        "--scenario", action="append", choices=[s["name"] for s in SCENARIOS]
    )
    parser.add_argument("--output", default=str(BIN_ROOT / "runs"))
    parser.add_argument(
        "--bytes",
        type=int,
        help="Payload bytes per run; default: 64 MiB, or 16 MiB for lossy-1000",
    )
    parser.add_argument("--down-poll-ms", type=int, default=1, help="Interval between client download polls (0..1000 ms)")
    args = parser.parse_args()
    if not 0 <= args.down_poll_ms <= 1000:
        parser.error("--down-poll-ms must be 0..1000")
    tcp_overrides = json.loads(args.tcp_sysctls.read_text()) if args.tcp_sysctls else {}
    allowed = {
        "net.ipv4.tcp_rmem",
        "net.ipv4.tcp_wmem",
        "net.ipv4.tcp_congestion_control",
    }
    if (
        not isinstance(tcp_overrides, dict)
        or not set(tcp_overrides) <= allowed
        or any(not isinstance(v, str) for v in tcp_overrides.values())
    ):
        parser.error(
            "--tcp-sysctls accepts only string values for tcp_rmem, tcp_wmem, and tcp_congestion_control"
        )
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    if args.bytes is not None and (
        args.bytes < 1 or (args.streams != 1 and args.bytes % 8 != 0)
    ):
        parser.error("--bytes must be positive and divisible by the stream count")
    if args.cpus:
        os.sched_setaffinity(0, {int(x) for x in args.cpus.split(",")})
    BIN_ROOT = args.binaries.resolve()
    root = pathlib.Path(args.output).resolve()
    if root.exists() and any(root.iterdir()):
        parser.error("--output must be a new or empty directory")
    root.mkdir(parents=True, exist_ok=True)
    lab = Lab(root, args.down_poll_ms)
    try:
        lab.setup()
        lab.configure_tcp(tcp_overrides)
        env = {
            "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "kernel": os.uname().release,
            "cpu_count": os.cpu_count(),
            "cpu_affinity": sorted(os.sched_getaffinity(0)),
            "process_accounting_hz": os.sysconf("SC_CLK_TCK"),
            "topology": "client+Telego namespace -> router namespace -> syntheticDC namespace; netem on router egress immediately before receiver interfaces; no host/VPS configuration changes",
            "sysctls": lab.tcp_settings(lab.p),
            "peer_sysctls": lab.tcp_settings(lab.d),
            "tcp_sysctl_overrides": tcp_overrides,
            "loss_seed_supported": False,
            "loss_replay_note": "Loss runs use independent kernel random draws and balanced mode order; no seed is supplied.",
            "synthetic_client_down_poll_coalescing_ms": args.down_poll_ms,
            "tc_version": lab.run("tc", "-V").stdout.strip(),
            "binary_sha256": {
                mode: hashlib.sha256(
                    (BIN_ROOT / (mode + ".test")).read_bytes()
                ).hexdigest()
                for mode in ["auto", "fixed"]
            },
        }
        (root / "environment.json").write_text(json.dumps(env, indent=2))
        scenarios = [
            s for s in SCENARIOS if not args.scenario or s["name"] in args.scenario
        ]
        plans = []
        if args.pilot:
            plans = [
                (SCENARIOS[0], 1, "upload", 0, "fixed"),
                (SCENARIOS[0], 1, "upload", 0, "auto"),
                (SCENARIOS[0], 1, "download", 1, "fixed"),
                (SCENARIOS[0], 8, "download", 1, "auto"),
            ]
        else:
            for s in scenarios:
                for direction in (
                    [args.direction] if args.direction else ["upload", "download"]
                ):
                    for streams in ([args.streams] if args.streams else [1, 8]):
                        for repeat in range(args.repeats):
                            modes = (
                                ["fixed", "auto"]
                                if repeat % 2 == 0
                                else ["auto", "fixed"]
                            )
                            for mode in modes:
                                plans.append((s, streams, direction, repeat, mode))
        failed = False
        for index, (s, streams, direction, repeat, mode) in enumerate(plans):
            print(
                json.dumps(
                    {
                        "event": "start",
                        "run": index + 1,
                        "of": len(plans),
                        "scenario": s["name"],
                        "streams": streams,
                        "direction": direction,
                        "mode": mode,
                        "repeat": repeat,
                    }
                ),
                flush=True,
            )
            amount = (
                args.bytes
                if args.bytes is not None
                else (16 << 20 if s["name"] == "lossy-1000" else 64 << 20)
            )
            result = lab.execute(s, mode, streams, direction, repeat, amount)
            print(
                json.dumps(
                    {
                        "event": "result",
                        "run": index + 1,
                        "status": result["status"],
                        "MiB_s": result.get("transfer", {}).get("MiB_s"),
                        "error": result.get("error"),
                    }
                ),
                flush=True,
            )
            if result["status"] != "pass":
                failed = True
                if not args.continue_on_failure:
                    raise RuntimeError("run failed; inspect " + str(root))
        if failed:
            raise RuntimeError("one or more runs failed; inspect " + str(root))
    finally:
        lab.close()


if __name__ == "__main__":
    main()
