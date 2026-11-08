# Happy Proof Kernel

**Technical preview · BSD-3-Clause**

Let a second AI client finish a Git task from durable, scoped work records. The GitHub example lets GPT propose an edit, publish a PR, and retry after an injected error. Claude starts a fresh session, reads the handoff through MCP, and verifies the same GitHub commit under a separate grant.

The kernel records the operation, one-time execution permit, exact candidate, and verification receipt in SQLite. The demo binds that record to a GitHub PR number and head SHA. It checks GitHub independently, matches the remote file bytes against the candidate, and runs a local behavior check once.

## Run the GitHub demo

**Prerequisites** · Python 3.11+, Git, Codex CLI and Claude Code with working model logins, and the official `cloudflared` CLI on your PATH. The reference integration run used macOS. Offline CI is configured for macOS and Linux.

1. Create a **dedicated private GitHub repository** on GitHub.com. Initialize it on `main` with only a README. It should contain only synthetic test data.
2. Create a **fine-grained GitHub token** restricted to that repository. Select the account that owns the repository. Set **Contents** and **Pull requests** to **Read and write**.
3. From the root of this checkout:

   ```sh
   python3 -m venv .venv
   . .venv/bin/activate
   python -m pip install -e '.[demo,test]'
   python -m pytest
   hpk-demo run --repo YOUR_ACCOUNT/YOUR_PRIVATE_TEST_REPO
   ```

   Paste the GitHub token into the hidden terminal prompt. The demo runs the logged-in model clients and opens a real, unmerged PR in the selected private repository. Your model clients may use your account's inference allowance. The script starts and stops a temporary Cloudflare Quick Tunnel.

The command prints the PR URL and a private `result.json` path under `.hpk-runs/`. The same run must report:

- GPT publication replay returns `already_published`.
- Claude returns `verified`, then `already_verified` for the same request.
- GitHub returns **one matching PR and one change commit** on the generated branch.
- The ledger records **one edit dispatch and one check dispatch**.

The first run adds a small synthetic `slug.py` baseline commit to `main` if needed. The one-change count applies to the PR's branch. Every new invocation uses a new branch and is a new experiment. The no-duplicate check concerns retries **within** one run.

## What the preview covers

| In this preview | Verification boundary |
| --- | --- |
| Work and grant model, SQLite ledger, Git staging, MCP handoff projection, integrity helpers | One fixed synthetic workflow with independent read-back |
| Temporary HTTPS MCP and separate publish/verify OAuth scopes | Test-issued RS256 client-credentials tokens are obtained by the driver and handed to the clients. Interactive OAuth login and third-party IdP integration are outside this demo. |
| GitHub REST fixture adapter and replay checks | The injected error occurs after the PR is recorded. GitHub Actions, protected-branch merge, GitHub App webhooks, and multi-host recovery are outside this preview. |

The code allowlist in the fixture accepts a tiny string transformation only. The local behavior test is not a general sandbox. See the [handoff contract](docs/handoff.md), [security boundaries](SECURITY.md), and the [sanitized reference run](docs/reference-run.json).

For setup and API details see [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), [Claude Code MCP](https://code.claude.com/docs/en/mcp), [fine-grained GitHub tokens](https://github.com/settings/personal-access-tokens/new), and [Cloudflare Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/).

## Troubleshooting

- **GitHub 404** · Confirm the token's resource owner, selected private repository and permissions. GitHub can return 404 when a token cannot read a private repository.
- **HTTPS address unavailable** · DNS propagation for the temporary hostname can take time. Inspect the run's `tunnel.log`; the runner waits for both health and unauthenticated rejection before starting publication.
- **A model does not call the expected tools** · Check the client login, CLI compatibility, and private JSONL traces. The runner reports success only after it checks the model calls, protected check receipt, and GitHub read-back.
- **The run stops after GitHub writes** · Inspect the printed run directory and GitHub branch before starting a new experiment. A new invocation creates a new branch.

The core imports without PyTorch or MCP. The `demo` extra installs the transport dependencies. Use a fresh virtual environment if you also work with the original HappyLM research package.
