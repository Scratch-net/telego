#!/usr/bin/env python3
"""Inject accept errors only into temporary test sources, never production code."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    root = Path(__file__).resolve().parent.parent
    module = root / "third_party/gnet"
    target = subprocess.check_output(["go", "env", "GOOS"], text=True).strip()
    if target != "linux":
        print("Skipping Linux accept fault-injection gate on " + target)
        return
    original = module / "pkg/socket/socket.go"
    source = original.read_text()
    needle = "return sysAccept(fd)"
    if source.count(needle) != 1:
        raise SystemExit("socket.Accept changed; review the fault-injection overlay")
    signature = "func Accept(fd int) (int, unix.Sockaddr, error) {"
    if source.count(signature) != 1:
        raise SystemExit("socket.Accept signature changed; review the overlay")
    hook = "var TelegoAcceptTestHook func(int) (int, unix.Sockaddr, error)\n\n"
    source = source.replace(signature, hook + signature)
    source = source.replace(needle, "if TelegoAcceptTestHook != nil {\n\t\treturn TelegoAcceptTestHook(fd)\n\t}\n\t" + needle)
    with tempfile.TemporaryDirectory(prefix="telego-accept-fault-") as directory:
        scratch = Path(directory)
        injected = scratch / "socket.go"
        injected.write_text(source)
        overlay = scratch / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {
            str(original): str(injected),
            str(module / "accept_fault_linux_test.go"): str(module / "testdata/accept_fault_regression_test.go"),
        }}))
        for mode in (("-race",), ("-race", "-tags=gc_opt"), ("-tags=poll_opt,gc_opt",)):
            print("Accept fault injection: " + " ".join(mode), flush=True)
            subprocess.run(["sh", str(root / "dist/test-go.sh"),
                            "-mod=readonly", "-overlay=" + str(overlay),
                            "-run=^TestTelegoAccept(Pending|Resource)", *mode, "."],
                           cwd=module, check=True, timeout=150)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
