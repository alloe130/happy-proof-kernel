"""Run the private GitHub fixture with the real Codex and Claude clients."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from . import fixture
from .clients import RemoteClients, require
from .files import atomic
from .github import GitHub, GitHubError, validate_target
from .report import verify


HEALTH = {"service": "hpk-isolated-mcp-fixture", "auth": "OAuth required for MCP"}
TUNNEL_ORIGIN = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
GITHUB_CREDENTIALS = {
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
}


def status(url, data=None):
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, None


def wait_for(probe, seconds, message):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = probe()
            if result:
                return result
        except (OSError, ValueError):
            pass
        time.sleep(0.4)
    raise TimeoutError(message)


def start(root, label, command, *, stdin=subprocess.DEVNULL, pass_fds=()):
    environment = {
        key: value for key, value in os.environ.items() if key not in GITHUB_CREDENTIALS
    }
    with (root / (label + ".log")).open("w", encoding="utf-8") as log:
        return subprocess.Popen(
            command,
            stdin=stdin,
            stdout=log,
            stderr=log,
            text=True,
            env=environment,
            pass_fds=pass_fds,
        )


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def serve(root, listener, base, label):
    fd = listener.fileno()
    return start(
        root,
        label,
        [
            sys.executable,
            "-m",
            "hpk_demo.server",
            str(root),
            "--base",
            base,
            "--fd",
            str(fd),
        ],
        pass_fds=(fd,),
    )


def run(root, api, tunnel_binary):
    fixture.init(root)
    for name in ("queue", "codex-client", "claude-client"):
        (root / name).mkdir(mode=0o700)
    client_config = root / "clients.json"
    atomic(
        client_config,
        {
            name: secrets.token_urlsafe(36)
            for name in (fixture.CLIENT_A, fixture.CLIENT_B)
        },
    )
    # Retain ownership of this loopback socket across the server restart.
    listener = socket.socket()
    bootstrap = tunnel = backend = bridge = None
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        loopback = f"http://127.0.0.1:{listener.getsockname()[1]}"
        bootstrap = serve(root, listener, loopback, "bootstrap")
        wait_for(
            lambda: (
                bootstrap.poll() is None
                and status(loopback + "/health") == (200, HEALTH)
            ),
            20,
            "The local fixture did not start",
        )
        require(
            status(loopback + "/mcp", b"{}")[0] == 401,
            "The local MCP must reject unauthenticated access",
        )
        # Start a Quick Tunnel without loading the user's other configurations.
        tunnel = start(
            root,
            "tunnel",
            [
                tunnel_binary,
                "--no-autoupdate",
                "--config",
                os.devnull,
                "tunnel",
                "--protocol",
                "http2",
                "--url",
                loopback,
            ],
        )

        def tunnel_base():
            if tunnel.poll() is not None:
                raise RuntimeError("cloudflared stopped before assigning a test URL")
            match = TUNNEL_ORIGIN.search(
                (root / "tunnel.log").read_text(encoding="utf-8")
            )
            return match.group() if match else None

        base = wait_for(tunnel_base, 40, "The temporary tunnel did not get a URL")
        stop(bootstrap)
        bootstrap = None
        backend = serve(root, listener, base, "mcp")
        wait_for(
            lambda: (
                backend.poll() is None and status(base + "/health") == (200, HEALTH)
            ),
            150,
            "The HTTPS endpoint is not reachable yet. Check DNS and the private tunnel log.",
        )
        require(
            status(base + "/mcp", b"{}")[0] == 401,
            "The remote MCP must reject unauthenticated access",
        )
        clients = RemoteClients(root, base)
        clients.probe()
        print("Remote HTTPS OAuth checks passed.", flush=True)

        target = api.seed()
        require(
            api.head(api.branch) is None and not api.matching_prs(),
            "Expected an unused test branch",
        )
        atomic(root / "repo.json", target)
        bridge = start(
            root,
            "github-bridge",
            [sys.executable, "-m", "hpk_demo.github", str(root)],
            stdin=subprocess.PIPE,
        )
        with bridge.stdin as pipe:
            pipe.write(api.token + "\n")
        print("Running GPT publication and replay.", flush=True)
        clients.run_a()
        print("Running Claude handoff and replay in a fresh session.", flush=True)
        clients.run_b()
        return verify(root, api.observe(target["base_sha"]))
    finally:
        stop(tunnel)
        stop(backend)
        stop(bootstrap)
        stop(bridge)
        listener.close()
        client_config.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["run"])
    parser.add_argument(
        "--repo", required=True, help="Dedicated private GitHub fixture, owner/name"
    )
    parser.add_argument(
        "--state-dir", type=Path, help="Path for a new private run directory"
    )
    args = parser.parse_args()
    run_id = uuid.uuid4().hex[:12]
    branch = "hpk-handoff-" + run_id
    try:
        validate_target(args.repo, branch)
        if sys.platform not in {"linux", "darwin"}:
            raise ValueError("The fixture currently supports Linux and macOS")
        for executable in ("git", "codex", "claude", "cloudflared"):
            if not shutil.which(executable):
                raise ValueError(f"Install {executable} and add it to PATH")
        root = (args.state_dir or Path(".hpk-runs") / run_id).expanduser().absolute()
        if root.exists() or root.is_symlink():
            raise ValueError(
                "Use a new state directory for each independent experiment"
            )
        root.parent.mkdir(parents=True, exist_ok=True)
        api = GitHub(
            getpass.getpass(
                "Fine-grained GitHub token for the test repository: "
            ).strip(),
            args.repo,
            branch,
        )
        api.validate_repo()
        api.audit_path = root / "github-api-events.jsonl"
        print(f"Private run state: {root}", flush=True)
        result = run(root, api, shutil.which("cloudflared"))
        print(
            json.dumps(
                {
                    "result": result["result"],
                    "pr": result["github"]["url"],
                    "report": str(root / "result.json"),
                },
                indent=2,
            )
        )
    except (
        GitHubError,
        OSError,
        RuntimeError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        parser.exit(1, f"Test stopped: {error}\n")


if __name__ == "__main__":
    main()
