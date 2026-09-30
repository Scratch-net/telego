#!/usr/bin/env python3
"""Exercise the shipped WEB fallback locations in an isolated Nginx container."""

import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("TELEGO_TEST_NGINX_IMAGE", "nginx:alpine")
HEADERS = {
    "Authorization": "Bearer synthetic-test-token",
    "Cookie": "session=synthetic-test-cookie",
    "Content-Type": "text/plain",
    "X-Up-Seq": "7",
    "X-Down-Cursor": "8",
    "X-Session-Token": "synthetic-test-token",
    "X-Carrier-Mode": "websocket",
    "X-Up-Ack": "9",
    "X-Lane-ID": "10",
    "Sec-WebSocket-Key": "synthetic-test-key",
    "Sec-WebSocket-Protocol": "tproxy-v1.synthetic-test-token",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Extensions": "synthetic-test-extension",
    "X-Forwarded-For": "192.0.2.1",
    "Forwarded": "for=192.0.2.1",
    "Connection": "upgrade",
    "Upgrade": "websocket",
}


def block(source, directive):
    start = source.index(directive)
    end = source.index("}", start) + 1
    return source[start:end]


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=60, **kwargs)


def check_template(label, http_path, server_path):
    http = (ROOT / http_path).read_text()
    server = (ROOT / server_path).read_text()
    maps = block(http, "map $http_upgrade")
    # Allow the old template through startup so it fails on observed behavior.
    if "map $request_uri" in http:
        maps += "\n" + block(http, "map $request_uri")
    locations = "\n".join(block(server, directive) for directive in (
        "location / {", "location @telego_ordinary {",
        "location @telego_sanitized {"))
    # The manual template has a port-80 redirect before its WEB ingress.
    if "proxy_pass http://telego_web;" not in locations:
        ingress = server.index("proxy_pass http://telego_web;")
        start = server.rfind("location / {", 0, ingress)
        locations = block(server[start:], "location / {") + "\n" + "\n".join(
            block(server, directive) for directive in (
                "location @telego_ordinary {", "location @telego_sanitized {"))
    echoes = ["$request", "args=$args", "probe=$http_x_probe",
              "length=$http_content_length"]
    echoes += [name + "=$http_" + name.lower().replace("-", "_")
               for name in HEADERS]
    config = """worker_processes 1;
pid /tmp/nginx.pid;
error_log stderr warn;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path /tmp/client;
    proxy_temp_path /tmp/proxy;
    fastcgi_temp_path /tmp/fastcgi;
    uwsgi_temp_path /tmp/uwsgi;
    scgi_temp_path /tmp/scgi;
""" + maps + """
    upstream telego_web { server 127.0.0.1:18081; }
    upstream public_site { server 127.0.0.1:18082; }
    server {
        listen 127.0.0.1:18080;
""" + locations + """
    }
    server {
        listen 127.0.0.1:18081;
        location / { return 419; }
        location /ordinary { return 418; }
    }
    server {
        listen 127.0.0.1:18082;
        return 200 """ + '"' + "|".join(echoes) + '";' + "\n    }\n}\n"
    name = "telego-test-nginx-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="telego-test-nginx-") as directory:
        # The container runs as an unprivileged user.
        os.chmod(directory, 0o755)
        path = Path(directory) / "nginx.conf"
        path.write_text(config)
        path.chmod(0o644)
        try:
            run("docker", "run", "--detach", "--name", name, "--network", "none",
                "--read-only", "--cap-drop", "ALL", "--user", "101:101",
                "--tmpfs", "/tmp:rw,nosuid,nodev",
                "--mount", f"type=bind,src={path},dst=/etc/nginx/nginx.conf,readonly",
                "--entrypoint", "nginx", IMAGE, "-g", "daemon off;")
            for attempt in range(50):
                try:
                    run("docker", "exec", name, "wget", "-qO-",
                        "http://127.0.0.1:18080/ready")
                    break
                except subprocess.CalledProcessError:
                    if attempt == 49:
                        raise RuntimeError(run("docker", "logs", name).stderr)
                    time.sleep(0.1)

            def request(uri):
                args = ["docker", "exec", name, "wget", "-qO-", "--post-data=body"]
                args += [f"--header={key}: {value}" for key, value in HEADERS.items()]
                response = run(*args, "http://127.0.0.1:18080" + uri).stdout.split("|")
                return response[0], dict(field.split("=", 1) for field in response[1:])

            paths = (
                "/api/v1/up",
                "/custom/path/api/v1/up",
                "/api/v1/up%3Fbridge=synthetic",
                "/escaped%20path",
                "/api/v1/up%0d%0aX-Probe:%20yes",
                "/api/v1/up%20HTTP/1.1%0d%0aX-Probe:%20yes%0d%0aX-Ignore:%20",
            )
            for uri in paths:
                line, fields = request(uri + "?bridge=synthetic&extra=1")
                assert line == f"GET {uri} HTTP/1.1", (label, uri, line)
                assert all(value == "" for value in fields.values()), (label, uri, fields)

            line, fields = request("/ordinary?site=value")
            assert line == "POST /ordinary?site=value HTTP/1.1", (label, line)
            # BusyBox wget adds its own Connection: close header.
            expected = {"args": "site=value", "probe": "", "length": "4", **HEADERS}
            expected["Connection"] = "close, upgrade"
            assert fields == expected, fields
            print(f"{label}: {len(paths)} sanitized cases and ordinary fallback passed")
        finally:
            subprocess.run(["docker", "rm", "--force", name], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=30)


if __name__ == "__main__":
    check_template("manual", "examples/web-proxy/nginx/nginx.conf",
                   "examples/web-proxy/nginx/nginx.conf")
    check_template("gateway", "examples/gateway/templates/nginx.conf",
                   "examples/gateway/templates/nginx-web-server.conf")
