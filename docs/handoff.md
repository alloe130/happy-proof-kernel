# GitHub handoff contract

The demo stores one work object, one edit action and one verification action in the kernel ledger. The remote MCP server applies its OAuth role check before it calls the local kernel. The GitHub adapter is restricted to the repository selected by the operator and a branch generated for that run.

| Tool | OAuth scope | Role |
| --- | --- | --- |
| `get_git_task` | `hpk:publish` | Reads the synthetic edit task and the pinned GitHub base SHA. |
| `publish_git_pr` | `hpk:publish` | Accepts the base SHA and full fixture replacement. It records the local candidate, publishes the matching GitHub change and stores the remote PR observation. |
| `get_github_handoff` | `hpk:verify` | Reads the objective, the GitHub PR observation and the versioned execution method from the ledger. |
| `verify_github_pr` | `hpk:verify` | Accepts the exact PR number, head SHA and checkpoint digest. It reads the PR and changed file again, compares the bytes, and runs the protected check under a fresh read grant. |

The handoff combines two records:

- `github` contains the remote PR number, base SHA, head SHA and hash of the changed file.
- `method` uses `happy-handoff.git/v1`. Its `action_id`, `evidence_digest`, `candidate_commit`, and `status` identify the local checkpoint. The local candidate commit and the GitHub head SHA are separate identifiers. The file hash binds the two.

The driver injects a tool error after GitHub publication and handoff state are recorded. With identical inputs, a publication retry reads back the same PR and returns `already_published`. After the verifier records a successful protected check, an identical verification retry reads GitHub again and returns `already_verified` without another check dispatch.

The protected check outcome is recorded in the kernel ledger and the result file. It does not create a GitHub review comment or merge the PR. The preview exercises one run on one machine. It does not guarantee recovery from every network failure, a process exit before the checkpoint, or competing writers outside the demo.
