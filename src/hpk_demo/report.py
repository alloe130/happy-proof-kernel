"""Verify the model call traces against GitHub and the kernel ledger."""

from __future__ import annotations

import json

from happylm.development import ContentAddressedArtifactStore
from happylm.ledger import SQLiteWorkLedger

from .clients import require
from .files import atomic, read
from .fixture import WORK


def rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def verify(root, observed):
    gpt = [
        e["item"]
        for e in rows(root / "gpt-remote.jsonl")
        if e["type"] == "item.completed"
    ]
    require(
        all(
            item["type"] in {"mcp_tool_call", "agent_message", "reasoning"}
            for item in gpt
        ),
        "GPT used a tool outside the MCP fixture",
    )
    calls = [item for item in gpt if item["type"] == "mcp_tool_call"]
    require(
        all(
            item["server"] == "hpk"
            and item["tool"] in {"get_git_task", "publish_git_pr"}
            for item in calls
        ),
        "Unexpected GPT MCP tool",
    )
    publishes = [item for item in calls if item["tool"] == "publish_git_pr"]
    require(
        len(publishes) == 2
        and calls[0]["tool"] == "get_git_task"
        and publishes[0]["arguments"] == publishes[1]["arguments"],
        "GPT did not replay the same publication",
    )
    require(
        "Injected reply loss" in json.dumps(publishes[0])
        and "already_published" in json.dumps(publishes[1]),
        "GPT's replay did not reuse the PR",
    )

    claude_events = rows(root / "claude-remote.jsonl")
    claude = [
        part
        for e in claude_events
        if e["type"] == "assistant"
        for part in e["message"]["content"]
        if part.get("type") == "tool_use"
    ]
    require(
        [part["name"] for part in claude]
        == [
            "mcp__hpk__get_github_handoff",
            "mcp__hpk__verify_github_pr",
            "mcp__hpk__verify_github_pr",
        ],
        "Claude did not follow the independent handoff and replay sequence",
    )
    require(
        claude[1]["input"] == claude[2]["input"],
        "Claude retried with different identifiers",
    )
    results = [
        json.loads(text["text"])
        for e in claude_events
        if e["type"] == "user"
        for part in e["message"]["content"]
        if part.get("type") == "tool_result"
        for text in part["content"]
        if text.get("type") == "text" and not part.get("is_error")
    ]
    handoff, first, replay = results
    require(
        handoff["method"]["status"] == "verification_pending"
        and [first["status"], replay["status"]] == ["verified", "already_verified"],
        "Unexpected Claude verification outcomes",
    )
    require(
        any(
            e["type"] == "result" and e.get("subtype") == "success"
            for e in claude_events
        ),
        "Claude did not finish successfully",
    )
    model = next(e["model"] for e in claude_events if e.get("subtype") == "init")

    pinned = read(root / "published.json")["github"]
    require(observed == pinned == handoff["github"], "GitHub PR or commit changed")
    require(
        all(
            value == observed[key]
            for item in (first, replay)
            for key, value in item.items()
            if key in observed
        ),
        "Claude verified a different PR",
    )
    require(
        observed["commit_count"] == observed["pr_count"] == 1,
        "Unexpected GitHub PR or commit count",
    )
    writes = [
        e
        for e in rows(root / "github-api-events.jsonl")
        if e["method"] in ("PUT", "POST")
    ]
    pr_writes = sum(e["method"] == "POST" and e["endpoint"] == "/pulls" for e in writes)
    candidate_writes = sum(
        e["method"] == "PUT" and e["branch"] == observed["branch"] for e in writes
    )
    require(pr_writes == candidate_writes == 1, "A retry repeated a GitHub write")

    evidence = []
    check_name = None
    with SQLiteWorkLedger(root / "work.sqlite") as ledger:
        artifacts = ContentAddressedArtifactStore(root / "artifacts")
        for operation in ledger.snapshot(WORK)["operations"]:
            for action in operation["actions"]:
                record = ledger.get_action(action["action_id"])
                events = ledger.events_for("action", action["action_id"])
                evidence.append(
                    {
                        "operation": record.request.operation,
                        "status": action["status"],
                        "dispatches": sum(
                            e.event_type == "dispatch.started" for e in events
                        ),
                    }
                )
                if record.request.operation == "verify_staged_candidate":
                    digest = next(
                        e.payload["result_digest"]
                        for e in events
                        if e.event_type == "dispatch.acknowledged"
                    )
                    (check,) = artifacts.get_json(digest)["checks"]
                    require(
                        check["passed"] is True, "The protected behavior check failed"
                    )
                    check_name = check["check_id"]
    require(
        check_name is not None
        and len(evidence) == 2
        and all(e["status"] == "verified" and e["dispatches"] == 1 for e in evidence),
        "The kernel did not record exactly one edit and one successful check",
    )

    result = {
        "result": "PASS",
        "transport": "Remote HTTPS Streamable HTTP MCP",
        "oauth": read(root / "oauth-probe.json"),
        "clients": {
            "GPT": "Codex CLI",
            "Claude": model,
            "claude_used_fresh_session": True,
        },
        "github": observed,
        "github_candidate_write_calls": candidate_writes,
        "github_pr_create_calls": pr_writes,
        "gpt_outcomes": ["injected reply loss after publication", "already_published"],
        "claude_outcomes": [first["status"], replay["status"]],
        "kernel_actions": evidence,
        "protected_check": {"name": check_name, "passed": True},
    }
    atomic(root / "result.json", result)
    return result
