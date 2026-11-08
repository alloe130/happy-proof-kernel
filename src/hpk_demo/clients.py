"""Drive the real clients with scoped OAuth access tokens over HTTPS."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .files import atomic, read
from .github import NoRedirect


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class RemoteClients:
    def __init__(self, root: Path, base: str):
        url = urllib.parse.urlsplit(base)
        if (
            url.scheme != "https"
            or not url.hostname
            or not url.hostname.endswith(".trycloudflare.com")
            or url.netloc != url.hostname
            or url.path
            or url.query
            or url.fragment
        ):
            raise ValueError("Expected the fresh HTTPS Quick Tunnel origin")
        self.root = root
        self.base = base
        self.url = base + "/mcp"
        self.clients = read(root / "clients.json")
        self.opener = urllib.request.build_opener(NoRedirect())

    def http(self, path, data=None, headers=None):
        request = urllib.request.Request(
            self.base + path, data=data, headers=headers or {}
        )
        try:
            with self.opener.open(request, timeout=18) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    def token(self, role, requested_resource=None, requested_scope=None):
        auth = base64.b64encode((role + ":" + self.clients[role]).encode()).decode()
        scope = "hpk:publish" if role == "client.ai-a" else "hpk:verify"
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "resource": requested_resource or self.url,
                "scope": requested_scope or "happy:mcp " + scope,
            }
        ).encode()
        return self.http(
            "/oauth/token",
            form,
            {
                "Authorization": "Basic " + auth,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

    def rpc(self, method, params, access=None):
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if access:
            headers["Authorization"] = "Bearer " + access
        data = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode()
        return self.http("/mcp", data, headers)

    def probe(self):
        http_code, meta = self.http("/.well-known/oauth-protected-resource/mcp")
        require(
            http_code == 200 and meta["resource"] == self.url,
            "Protected resource discovery did not match",
        )
        issuer_code, issuer = self.http("/.well-known/oauth-authorization-server")
        require(
            issuer_code == 200
            and issuer["token_endpoint"] == self.base + "/oauth/token",
            "OAuth token endpoint did not match",
        )
        require(
            meta["authorization_servers"] == [issuer["issuer"]],
            "OAuth issuer discovery did not match",
        )
        jwks_code, jwks = self.http("/jwks.json")
        require(
            jwks_code == 200 and jwks["keys"][0]["alg"] == "RS256",
            "Expected an RS256 test key",
        )
        unauthenticated = self.rpc("tools/list", {})[0]
        invalid = self.rpc("tools/list", {}, "invalid.test.token")[0]
        wrong_scope = self.token(
            "client.ai-b", requested_scope="happy:mcp hpk:publish"
        )[0]
        wrong_resource = self.token(
            "client.ai-a", requested_resource=self.base + "/different"
        )[0]
        require(
            (unauthenticated, invalid, wrong_scope, wrong_resource)
            == (401, 401, 400, 400),
            "OAuth rejection probes failed",
        )
        observed = {}
        for role in self.clients:
            status, issued = self.token(role)
            require(
                status == 200 and issued["token_type"] == "Bearer",
                "Could not acquire a scoped OAuth token",
            )
            code, answer = self.rpc(
                "tools/call",
                {"name": "oauth_identity", "arguments": {}},
                issued["access_token"],
            )
            require(
                code == 200 and not answer["result"].get("isError"),
                "OAuth identity probe failed",
            )
            result = answer["result"]
            identity = result.get("structuredContent") or json.loads(
                result["content"][0]["text"]
            )
            require(
                identity["client"] == role,
                "OAuth identity differs from the expected role",
            )
            observed[role] = identity
        wrong_role_access = self.token("client.ai-b")[1]["access_token"]
        code, denied = self.rpc(
            "tools/call", {"name": "get_git_task", "arguments": {}}, wrong_role_access
        )
        require(
            code == 200 and denied["result"]["isError"] is True,
            "Claude unexpectedly accessed a publish tool",
        )
        evidence = {
            "tls_remote": True,
            "issuer": issuer["issuer"],
            "resource": meta["resource"],
            "discovered_authorization_servers": meta["authorization_servers"],
            "grant": "client_credentials",
            "jwt_algorithm": jwks["keys"][0]["alg"],
            "unauthenticated_http": unauthenticated,
            "invalid_token_http": invalid,
            "wrong_scope_http": wrong_scope,
            "wrong_resource_http": wrong_resource,
            "claude_token_cannot_call_gpt_tool": True,
            "identities": observed,
        }
        atomic(self.root / "oauth-probe.json", evidence)
        return evidence

    def launch(self, cmd, name, cwd, prompt, access):
        env = {
            name: value
            for name, value in os.environ.items()
            if name
            not in {
                "GH_TOKEN",
                "GITHUB_TOKEN",
                "GH_ENTERPRISE_TOKEN",
                "GITHUB_ENTERPRISE_TOKEN",
            }
        }
        env["HPK_REMOTE_OAUTH_ACCESS_TOKEN"] = access
        with (
            (self.root / f"{name}.jsonl").open("w", encoding="utf-8") as out,
            (self.root / f"{name}.err").open("w", encoding="utf-8") as err,
        ):
            result = subprocess.run(
                cmd,
                input=prompt,
                text=True,
                stdout=out,
                stderr=err,
                timeout=240,
                cwd=cwd,
                env=env,
            )
        if result.returncode:
            raise RuntimeError(
                f"{name} exited with code {result.returncode}; inspect the private run logs"
            )

    def run_a(self):
        status, issued = self.token("client.ai-a")
        require(status == 200, "OAuth token issuance failed")
        names = ["get_git_task", "publish_git_pr"]
        cmd = [
            shutil.which("codex"),
            "-a",
            "never",
            "exec",
            "--skip-git-repo-check",
            "--ephemeral",
            "--ignore-user-config",
            "--sandbox",
            "read-only",
            "--json",
            "-c",
            "mcp_servers.hpk.url=" + json.dumps(self.url),
            "-c",
            'mcp_servers.hpk.bearer_token_env_var="HPK_REMOTE_OAUTH_ACCESS_TOKEN"',
            "-c",
            "mcp_servers.hpk.enabled_tools=" + json.dumps(names),
            *[
                item
                for name in names
                for item in (
                    "-c",
                    f'mcp_servers.hpk.tools.{name}.approval_mode="approve"',
                )
            ],
            "-c",
            "mcp_servers.hpk.required=true",
            "-c",
            "mcp_servers.hpk.tool_timeout_sec=80",
            "-",
        ]
        self.launch(
            cmd,
            "gpt-remote",
            self.root / "codex-client",
            "Use only the hpk MCP tools. Call get_git_task, then independently write the full slug.py "
            "replacement for the task. Use def slugify(value) with a single return expression, built "
            "only from the input and strip(), lower(), or replace(' ', '-'). Call publish_git_pr with "
            "the exact base and replacement. The first publication can intentionally return an injected "
            "lost-reply error after GitHub commits it. If so, repeat publish_git_pr exactly once with "
            "the same arguments. Report the returned PR number and head SHA. Do not use other tools.",
            issued["access_token"],
        )
        log = (self.root / "mcp-events.jsonl").read_text()
        if "gpt_publish_replayed" not in log:
            raise RuntimeError("GPT did not finish the real GitHub publication retry.")

    def run_b(self):
        status, issued = self.token("client.ai-b")
        require(status == 200, "OAuth token issuance failed")
        config = {
            "mcpServers": {
                "hpk": {
                    "type": "http",
                    "url": self.url,
                    "headers": {
                        "Authorization": "Bearer ${HPK_REMOTE_OAUTH_ACCESS_TOKEN}"
                    },
                }
            }
        }
        config_path = self.root / "claude-remote-mcp.json"
        atomic(config_path, config)
        cmd = [
            shutil.which("claude"),
            "-p",
            "--restricted",
            "--setting-sources",
            "",
            "--strict-mcp-config",
            "--tools",
            "",
            "--mcp-config",
            str(config_path),
            "--no-session-persistence",
            "--max-turns",
            "10",
            "--output-format",
            "stream-json",
            "--verbose",
            "--allowedTools",
            "mcp__hpk__get_github_handoff,mcp__hpk__verify_github_pr",
        ]
        self.launch(
            cmd,
            "claude-remote",
            self.root / "claude-client",
            "You are in a fresh GitHub handoff verification session. Use only the hpk MCP tools. Call "
            "get_github_handoff to discover the work. Read the returned PR number, head SHA, and evidence "
            "digest. Call verify_github_pr with those exact identifiers, using the method's evidence "
            "digest for checkpoint_digest. Repeat the exact verification once to test duplicate suppression. "
            "Report both statuses and the PR number and SHA. Do not create or modify GitHub data.",
            issued["access_token"],
        )
        log = (self.root / "mcp-events.jsonl").read_text()
        if "claude_verify_replayed" not in log or "claude_verified_pr" not in log:
            raise RuntimeError(
                "Claude did not finish the real GitHub verification retry."
            )
