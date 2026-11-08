# Security boundaries

This repository is a technical preview for synthetic data and a dedicated private GitHub repository. Do not point it at a production repository or feed it arbitrary executable code.

- GPT and Claude receive separate short-lived OAuth access tokens scoped to this test resource. The server checks the issuer, audience, signature, expiration, and tool role.
- The GitHub token is accepted at a hidden terminal prompt and passed to the local GitHub bridge over a pipe. It is not sent to either model or to the public MCP endpoint. Restrict the token to the dedicated fixture repository.
- Run folders can contain model transcripts, private repository identifiers, SQLite state, and receipts. Keep these folders private. The sample evidence in `docs/` is a deliberately redacted summary.
- The OAuth issuer, single-machine SQLite setup, fixture code validator, and local protected check are demo components. The kernel's HMAC receipts require a shared verification key. This preview makes no production sandbox, third-party attestation, or failover claim.

If a published GitHub repository enables private vulnerability reporting, use its **Security → Report a vulnerability** feature. Do not include tokens, private traces, or customer data in public issues.
