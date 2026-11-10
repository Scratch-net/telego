#!/usr/bin/env python3
"""Build equal Telego test executables with different Linux socket policies."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    source = Path(__file__).resolve().parent
    repo = source.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=repo / ".local/socket-autotune")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    socket_source = repo / "pkg/netx/conn_linux.go"
    text = socket_source.read_text()
    marker = "\t// Leave receive and send buffers under kernel TCP autotuning."
    if text.count(marker) != 1 or "SO_SNDBUF" in text or "SO_RCVBUF" in text:
        raise SystemExit(
            "Expected the Linux autotuning implementation. Inspect conn_linux.go before use."
        )
    fixed = text.replace(
        marker,
        """\t// Reproduce the previous 512 KiB buffer requests for this control executable.
\tif err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 512*1024); err != nil {
\t\treturn
\t}
\tif err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 512*1024); err != nil {
\t\treturn
\t}""",
    )
    fixed_path = output / "fixed_socket_linux.go.txt"
    fixed_path.write_text(fixed)
    virtual_test = str(repo / "cmd/telego/synthetic_socket_policy_test.go")
    replacements = {virtual_test: str(source / "harness_test.go.txt")}
    env = os.environ.copy()
    env.setdefault("GOMAXPROCS", "2")
    for mode in ("auto", "fixed"):
        overlay = output / (mode + "-overlay.json")
        overlay.write_text(
            json.dumps(
                {
                    "Replace": replacements
                    | ({str(socket_source): str(fixed_path)} if mode == "fixed" else {})
                },
                indent=2,
            )
        )
        subprocess.run(
            [
                "go",
                "test",
                "-mod=readonly",
                "-c",
                "-tags=poll_opt,gc_opt",
                "-overlay=" + str(overlay),
                "-o",
                str(output / (mode + ".test")),
                "./cmd/telego",
            ],
            cwd=repo,
            env=env,
            check=True,
        )

    files = [
        source / "harness_test.go.txt",
        source / "run.py",
        Path(__file__).resolve(),
        socket_source,
        fixed_path,
        output / "auto.test",
        output / "fixed.test",
    ]
    manifest = {
        "sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        "go_version": subprocess.check_output(["go", "version"], text=True).strip(),
        "commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip(),
        "control": "Same source and build flags. Only the fixed executable requests 512 KiB SO_RCVBUF and SO_SNDBUF.",
    }
    (output / "build.json").write_text(json.dumps(manifest, indent=2))
    (output / "source.diff").write_bytes(
        subprocess.check_output(["git", "diff", "--no-ext-diff"], cwd=repo)
    )
    print(output)


if __name__ == "__main__":
    main()
