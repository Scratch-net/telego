#!/usr/bin/env python3
"""Run the opt-in ME peer, capped proxy server, and external driver together.

Build the two Go test binaries before invoking this runner. Run this parent in
the host user session: its children must share one loopback network namespace.
Only the server enters a transient systemd user scope. No source or production
configuration is changed. Raw artifacts stay under /tmp/telego-pressure.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import urllib.request


PROFILES = {"512M": 512 << 20, "1G": 1 << 30, "2G": 2 << 30}
POOLS = {"baseline": 2 * (32 * 1024 * 1024 + 16 * 1024), "candidate": 69_231_118}
MAX_JSON_BYTES = 64 << 20


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def progress(message):
    print(f"[{utc_now()}] {message}", flush=True)


def read_json(path):
    with open(path, "rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError(f"JSON artifact exceeds {MAX_JSON_BYTES} bytes: {path}")
    return json.loads(data)


def write_json(path, value):
    temporary = Path(str(path) + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def binary_identity(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    stat = path.stat()
    return {"Path": str(path), "SHA256": digest.hexdigest(), "Bytes": stat.st_size, "ModifiedNanoseconds": stat.st_mtime_ns}


def control(address, path, method="GET", timeout=2):
    request = urllib.request.Request("http://" + address + path, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("control response exceeds bounded JSON size")
    return json.loads(data)


def cgroup_for(pid):
    for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            return line[3:]
    raise RuntimeError(f"PID {pid} does not use cgroup v2")


def keyed_numbers(text):
    return {key: int(value) for key, value in (line.split() for line in text.splitlines())}


def inside_cgroup(path, parent):
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def cgroup_counters(cgroup):
    result = {}
    for name in ("memory.current", "memory.peak", "memory.stat", "memory.events", "memory.events.local", "memory.swap.current", "pids.current", "cpu.stat"):
        text = (cgroup / name).read_text().strip()
        result[name] = keyed_numbers(text) if ".stat" in name or ".events" in name else int(text)
    return result


def has_oom(counters):
    return any(counters.get("memory.events", {}).get(name, 0) for name in ("oom", "oom_kill", "oom_group_kill"))


def resources(pid, cgroup):
    status = Path(f"/proc/{pid}/status").read_text()
    fields = {}
    for line in status.splitlines():
        name, separator, value = line.partition(":")
        if separator and name in {"VmRSS", "VmHWM", "VmPeak", "VmSize", "Threads"}:
            parts = value.split()
            fields[name] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
    result = {"At": utc_now(), "PID": pid, "Proc": fields, "ProcUnits": "bytes except Threads", "ProcStatus": status}
    result.update(cgroup_counters(cgroup))
    return result


def run_command(command, timeout=10):
    return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)


def wait_ready(path, process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"child exited {process.returncode} before readiness: {path}")
        try:
            return read_json(path)
        except FileNotFoundError:
            time.sleep(0.02)
    raise TimeoutError(f"readiness deadline expired: {path}")


def reap(process, timeout=5):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


class Sampler:
    def __init__(self, directory, ready, cgroup, interval):
        self.directory = directory
        self.ready = ready
        self.cgroup = cgroup
        self.interval = interval
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, name="pressure-resource-sampler", daemon=True)
        self.phases = {}
        self.peaks = {}
        self.errors = []
        self.error_count = 0
        self.samples = 0
        self.last_name = ""
        self.first_sample = threading.Event()
        self.latest = None
        self.last_sample_at = None
        self.maximum_gap = 0
        self.maximum_duration = 0

    def run(self):
        heartbeat = time.monotonic()
        with open(self.directory / "resources.jsonl", "w") as output:
            while not self.stop_event.is_set():
                started = time.monotonic()
                try:
                    phase = {"Name": "startup", "Snapshot": self.ready["Startup"]}
                    try:
                        phase = read_json(self.directory / "driver-progress.json")
                    except FileNotFoundError:
                        pass
                    sample = resources(self.ready["PID"], self.cgroup)
                    sample["Phase"] = phase["Name"]
                    sample["Server"] = control(self.ready["ControlAddress"], "/snapshot")
                    output.write(json.dumps(sample, separators=(",", ":")) + "\n")
                    output.flush()
                    self.samples += 1
                    finished = time.monotonic()
                    if self.last_sample_at is not None:
                        self.maximum_gap = max(self.maximum_gap, finished - self.last_sample_at)
                    self.last_sample_at = finished
                    self.maximum_duration = max(self.maximum_duration, finished - started)
                    self.latest = sample
                    self.first_sample.set()
                    for key, value in (("rss", sample["Proc"].get("VmRSS", 0)), ("cgroup_current", sample["memory.current"]), ("cgroup_peak", sample["memory.peak"]), ("pool", sample["Server"]["Pool"]["UsedBytes"])):
                        if key not in self.peaks or value > self.peaks[key]["Value"]:
                            self.peaks[key] = {"Value": value, "Sample": sample}
                    if phase["Name"] != self.last_name:
                        self.last_name = phase["Name"]
                        self.phases[self.last_name] = {"DriverBoundary": phase, "ExternalObservation": sample}
                        progress(f"phase={self.last_name} pool={sample['Server']['Pool']['UsedBytes']} rss={sample['Proc'].get('VmRSS', 0)} cgroup={sample['memory.current']}")
                    elif time.monotonic() - heartbeat >= 5:
                        progress(f"sampling phase={self.last_name} pool={sample['Server']['Pool']['UsedBytes']} cgroup_peak={sample['memory.peak']}")
                        heartbeat = time.monotonic()
                except Exception as error:
                    self.error_count += 1
                    if len(self.errors) < 32:
                        self.errors.append({"At": utc_now(), "Error": str(error)})
                self.stop_event.wait(max(0, self.interval - (time.monotonic() - started)))

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("resource sampler did not stop")


def commands(args, directory, profile, pool, unit):
    peer = [str(args.peer_binary), "-test.run=^TestResponsePressurePeerProcess$", "-test.count=1", f"-test.timeout={args.timeout + 120}s",
            f"-me-pressure-peer-ready={directory / 'peer-ready.json'}", "-me-pressure-peer-links=256", f"-me-pressure-peer-timeout={args.timeout + 90}s"]
    server_flags = [str(args.gproxy_binary), "-test.run=^TestMiddleEndPressureProcess$", "-test.count=1", f"-test.timeout={args.timeout + 90}s", "-me-pressure-role=server",
                    f"-me-pressure-peer={directory / 'peer-ready.json'}", f"-me-pressure-ready={directory / 'server-ready.json'}", f"-me-pressure-result={directory / 'server-final.json'}",
                    f"-me-pressure-links={args.links}", f"-me-pressure-pool={pool}", f"-me-pressure-timeout={args.timeout}s"]
    if args.send_buffer is not None:
        server_flags.append(f"-me-pressure-send-buffer={args.send_buffer}")
    server = ["systemd-run", "--user", "--scope", "--quiet", "--unit=" + unit,
              "--property=MemoryMax=" + profile, "--property=MemorySwapMax=0", "--property=CPUQuota=200%", "--property=TasksMax=512",
              "--property=MemoryAccounting=yes", "--property=CPUAccounting=yes", "--property=TasksAccounting=yes"] + server_flags
    driver = [str(args.gproxy_binary), "-test.run=^TestMiddleEndPressureProcess$", "-test.count=1", f"-test.timeout={args.timeout + 10}s", "-me-pressure-role=driver",
              f"-me-pressure-peer={directory / 'peer-ready.json'}", f"-me-pressure-ready={directory / 'server-ready.json'}", f"-me-pressure-result={directory / 'driver-result.json'}",
              f"-me-pressure-progress={directory / 'driver-progress.json'}", f"-me-pressure-scenario={args.scenario}", f"-me-pressure-clients={args.clients}",
              f"-me-pressure-batch={args.batch}", f"-me-pressure-size={args.size}", f"-me-pressure-waves={args.waves}", f"-me-pressure-pause={args.pause}",
              f"-me-pressure-all-paused={str(args.all_paused).lower()}", f"-me-pressure-receive-buffer={args.receive_buffer}", f"-me-pressure-timeout={args.timeout}s"]
    return {"Peer": peer, "Server": server, "Driver": driver}


def verify_scope(pid, unit, profile):
    path = cgroup_for(pid)
    if not path.endswith("/" + unit):
        raise RuntimeError(f"server PID {pid} is outside requested scope {unit}: {path}")
    cgroup = Path("/sys/fs/cgroup") / path.lstrip("/")
    settings = {name: (cgroup / name).read_text().strip() for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    quota, period = settings["cpu.max"].split()
    if settings["memory.max"] != str(PROFILES[profile]) or settings["memory.swap.max"] != "0" or settings["pids.max"] != "512" or quota == "max" or int(quota) != 2 * int(period):
        raise RuntimeError(f"cgroup limits were not applied: {settings}")
    return cgroup, settings


def run_profile(args, profile, pool_name, pool):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    name = f"{stamp}-{profile}-{pool_name}-{args.scenario}-{args.links}links-{args.clients}clients"
    directory = args.output / name
    directory.mkdir(parents=True)
    unit = f"telego-pressure-{os.getpid()}-{stamp}.scope"
    calls = commands(args, directory, profile, pool, unit)
    summary = {"StartedAt": utc_now(), "Profile": profile, "PoolName": pool_name, "PoolBytes": pool, "Unit": unit, "Commands": calls, "Environment": {"GOMAXPROCS": "2"}, "EnvironmentRemoved": ["GOMEMLIMIT"], "Outcome": "failed"}
    summary["Binaries"] = {"Peer": binary_identity(args.peer_binary), "ServerAndDriver": binary_identity(args.gproxy_binary)}
    write_json(directory / "manifest.json", summary)
    processes = {"Peer": None, "Server": None, "Driver": None}
    logs = []
    sampler = None
    peer_ready = server_ready = cgroup = None
    progress(f"start profile={profile} pool={pool_name}:{pool} output={directory}")
    env = os.environ | {"GOMAXPROCS": "2"}
    env.pop("GOMEMLIMIT", None)

    def start(role):
        stream = open(directory / (role.lower() + ".log"), "w")
        logs.append(stream)
        process = subprocess.Popen(calls[role], stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, env=env)
        processes[role] = process
        return process

    try:
        peer_process = start("Peer")
        peer_ready = wait_ready(directory / "peer-ready.json", peer_process, 15)
        progress(f"peer ready pid={peer_ready['PID']}")
        server_process = start("Server")
        server_ready = wait_ready(directory / "server-ready.json", server_process, 45)
        cgroup, settings = verify_scope(server_ready["PID"], unit, profile)
        identities = {"Runner": {"PID": os.getpid(), "Cgroup": cgroup_for(os.getpid())}, "Peer": {"PID": peer_ready["PID"], "Cgroup": cgroup_for(peer_ready["PID"])}, "Server": {"PID": server_ready["PID"], "Cgroup": cgroup_for(server_ready["PID"])}}
        if any(inside_cgroup(identities[role]["Cgroup"], identities["Server"]["Cgroup"]) for role in ("Runner", "Peer")):
            raise RuntimeError("generator/runner isolation failed")
        summary["Cgroup"], summary["AppliedLimits"] = str(cgroup), settings
        summary["Startup"] = {"Resources": resources(server_ready["PID"], cgroup), "Server": server_ready["Startup"]}
        sampler = Sampler(directory, server_ready, cgroup, args.sample_interval)
        sampler.thread.start()
        if not sampler.first_sample.wait(timeout=5):
            raise RuntimeError("no successful resource sample before workload")
        driver_process = start("Driver")
        identities["Driver"] = {"PID": driver_process.pid, "Cgroup": cgroup_for(driver_process.pid)}
        write_json(directory / "identity.json", identities)
        if inside_cgroup(identities["Driver"]["Cgroup"], identities["Server"]["Cgroup"]):
            raise RuntimeError("load generator entered the server memory scope")
        deadline = time.monotonic() + args.timeout + 5
        while driver_process.poll() is None:
            if server_process.poll() is not None:
                raise RuntimeError(f"server exited during workload: {server_process.returncode}")
            if peer_process.poll() is not None:
                raise RuntimeError(f"peer exited during workload: {peer_process.returncode}")
            if time.monotonic() >= deadline:
                raise TimeoutError("driver exceeded bounded workload deadline")
            time.sleep(0.05)
        if (directory / "driver-result.json").exists():
            summary["DriverResult"] = read_json(directory / "driver-result.json")
        if driver_process.returncode != 0:
            raise RuntimeError(f"driver failed: {driver_process.returncode}; see driver.log")
        summary["BeforeShutdown"] = {"Resources": resources(server_ready["PID"], cgroup), "Server": control(server_ready["ControlAddress"], "/snapshot")}
        summary["PeerBeforeShutdown"] = control(peer_ready["ControlAddress"], "/status")
        if summary["PeerBeforeShutdown"]["Errors"] or summary["PeerBeforeShutdown"]["RejectedLinks"]:
            raise RuntimeError("peer reported protocol errors or rejected links")
        if has_oom(summary["BeforeShutdown"]["Resources"]):
            raise RuntimeError("server cgroup recorded OOM activity")
        sampler.stop()
        if sampler.samples == 0:
            raise RuntimeError("zero successful resource samples")
        control(server_ready["ControlAddress"], "/shutdown", "POST", timeout=5)
        server_process.wait(timeout=30)
        summary["ServerFinal"] = read_json(directory / "server-final.json")
        if server_process.returncode != 0:
            raise RuntimeError(f"server cleanup failed: {server_process.returncode}; see server.log")
        summary["PeerFinal"] = control(peer_ready["ControlAddress"], "/status")
        if summary["PeerFinal"]["Errors"] or summary["PeerFinal"]["RejectedLinks"]:
            raise RuntimeError("peer reported errors during cleanup")
        control(peer_ready["ControlAddress"], "/quit", "POST")
        peer_process.wait(timeout=10)
        if peer_process.returncode != 0:
            raise RuntimeError(f"peer cleanup failed: {peer_process.returncode}")
        summary["Outcome"] = "passed"
    except Exception as error:
        summary["Error"] = str(error)
        progress(f"failed profile={profile} pool={pool_name}: {error}")
    finally:
        cleanup_errors = []

        def cleanup(label, action):
            try:
                return action()
            except Exception as error:
                cleanup_errors.append({"Step": label, "Error": str(error)})
                return None

        if sampler is not None:
            cleanup("stop resource sampler", sampler.stop)
            summary["Sampling"] = {"Samples": sampler.samples, "Peaks": sampler.peaks, "Phases": sampler.phases, "LastSample": sampler.latest, "MaximumGapSeconds": sampler.maximum_gap, "MaximumDurationSeconds": sampler.maximum_duration, "ErrorCount": sampler.error_count, "Errors": sampler.errors}
            if sampler.samples == 0:
                summary["Outcome"] = "failed"
        if cgroup is not None and server_ready is not None and processes["Server"].poll() is None:
            try:
                summary["FinalLiveResources"] = resources(server_ready["PID"], cgroup)
            except (OSError, ValueError) as error:
                summary["FinalLiveResourcesError"] = str(error)
        final_unit = cleanup("read final systemd result", lambda: run_command(["systemctl", "--user", "show", unit, "--property=Result,ActiveState,SubState,ControlGroup,MemoryCurrent,MemoryPeak"], timeout=5))
        if final_unit is not None:
            summary["FinalSystemdState"] = {"Code": final_unit.returncode, "Output": final_unit.stdout}
            if cgroup is None:
                for line in final_unit.stdout.splitlines():
                    key, _, value = line.partition("=")
                    if key == "ControlGroup" and value.endswith("/" + unit):
                        cgroup = Path("/sys/fs/cgroup") / value.lstrip("/")
        if cgroup is not None:
            try:
                summary["FinalCgroupCounters"] = cgroup_counters(cgroup)
                if has_oom(summary["FinalCgroupCounters"]):
                    summary["Outcome"] = "failed"
                    summary.setdefault("Error", "server cgroup recorded OOM activity")
            except OSError as error:
                summary["FinalCgroupCountersError"] = str(error)
        counter_sources = [summary.get("Startup", {}).get("Resources", {}), summary.get("BeforeShutdown", {}).get("Resources", {}), summary.get("FinalCgroupCounters", {})]
        if sampler is not None and sampler.latest is not None:
            counter_sources.append(sampler.latest)
        observed_max_events = [source["memory.events"].get("max", 0) for source in counter_sources if "memory.events" in source]
        summary["MemoryMaxEventsObserved"] = max(observed_max_events) if observed_max_events else None
        cleanup("stop driver", lambda: reap(processes["Driver"]))
        if server_ready is not None and processes["Server"].poll() is None:
            try:
                control(server_ready["ControlAddress"], "/shutdown", "POST", timeout=3)
                processes["Server"].wait(timeout=15)
            except Exception:
                pass
        stop = cleanup("stop server scope", lambda: run_command(["systemctl", "--user", "stop", unit], timeout=15))
        if stop is not None:
            summary["ScopeStop"] = {"Code": stop.returncode, "Output": stop.stdout}
        cleanup("reap server", lambda: reap(processes["Server"]))
        if peer_ready is not None and processes["Peer"].poll() is None:
            try:
                control(peer_ready["ControlAddress"], "/quit", "POST")
                processes["Peer"].wait(timeout=5)
            except Exception:
                pass
        cleanup("reap peer", lambda: reap(processes["Peer"]))
        if cleanup_errors:
            summary["CleanupErrors"] = cleanup_errors
            summary["Outcome"] = "failed"
        summary["ExitCodes"] = {name: process.returncode if process is not None else None for name, process in processes.items()}
        summary["EndedAt"] = utc_now()
        write_json(directory / "summary.json", summary)
        for stream in logs:
            stream.close()
    progress(f"done outcome={summary['Outcome']} profile={profile} pool={pool_name}")
    return {"Directory": str(directory), "Outcome": summary["Outcome"], "Error": summary.get("Error")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", nargs="+", choices=PROFILES, default=list(PROFILES))
    parser.add_argument("--pool", action="append", choices=POOLS, help="Repeat to compare baseline and candidate; default candidate (selected response default)")
    parser.add_argument("--links", type=int, choices=(1, 4, 48), default=4)
    parser.add_argument("--clients", type=int, default=1000)
    parser.add_argument("--batch", type=int, default=0)
    parser.add_argument("--size", type=int, default=65536)
    parser.add_argument("--waves", type=int, default=1)
    parser.add_argument("--pause", default="500ms")
    parser.add_argument("--all-paused", action="store_true", help="Pause every native reader; default mixes fast and paused readers")
    parser.add_argument("--receive-buffer", type=int, default=65536, help="Native client SO_RCVBUF request (4096..65536)")
    parser.add_argument("--send-buffer", type=int, help="Optional server SO_SNDBUF override (0 uses the production default; requires the updated harness binary)")
    parser.add_argument("--scenario", choices=("native", "http", "ws", "rotation", "exhaustion", "rotation_exhaustion"), default="native")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--sample-interval", type=float, default=0.05)
    parser.add_argument("--peer-binary", type=Path, default=Path("/tmp/telego-pressure/middleend.test"))
    parser.add_argument("--gproxy-binary", type=Path, default=Path("/tmp/telego-pressure/gproxy.test"))
    parser.add_argument("--output", type=Path, default=Path("/tmp/telego-pressure"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.clients <= 1000 or not 0 <= args.batch <= 1000 or not 1 <= args.waves <= 10 or not 4 <= args.size <= 1_044_480 or args.size % 4 or not 10 <= args.timeout <= 1800 or not 0.01 <= args.sample_interval <= 1:
        parser.error("clients, batch, packet size, waves, timeout, or sampling interval exceed harness bounds")
    if not 4096 <= args.receive_buffer <= 65536:
        parser.error("receive buffer must be between 4096 and 65536 bytes")
    if args.send_buffer is not None and not 0 <= args.send_buffer <= 65536:
        parser.error("send buffer must be between 0 and 65536 bytes")
    args.output = args.output.resolve()
    if args.output != Path("/tmp/telego-pressure") and Path("/tmp/telego-pressure") not in args.output.parents:
        parser.error("raw outputs must stay under /tmp/telego-pressure")
    args.peer_binary, args.gproxy_binary = args.peer_binary.resolve(), args.gproxy_binary.resolve()
    if args.dry_run:
        print(json.dumps(commands(args, args.output / "preview", args.profiles[0], POOLS[(args.pool or ["candidate"])[0]], "telego-pressure-preview.scope"), indent=2))
        return 0
    if sys.platform != "linux" or not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        parser.error("Linux cgroup v2 is required")
    for binary in (args.peer_binary, args.gproxy_binary):
        if not os.access(binary, os.X_OK):
            parser.error(f"precompiled executable is missing: {binary}")
    user_manager = run_command(["systemctl", "--user", "show", "--property=Version", "--value"])
    if user_manager.returncode != 0:
        parser.error("systemd user manager is unavailable; run this parent in the host user session")
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    results = []
    for pool_name in dict.fromkeys(args.pool or ["candidate"]):
        for profile in dict.fromkeys(args.profiles):
            results.append(run_profile(args, profile, pool_name, POOLS[pool_name]))
    args.output.mkdir(parents=True, exist_ok=True)
    write_json(args.output / f"run-index-{os.getpid()}.json", results)
    return int(any(result["Outcome"] != "passed" for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
