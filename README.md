# Daigrin

Daigrin is a concise, developer-focused coding assistant that provides clear, actionable answers, prefers examples and code snippets, and asks clarifying questions when needed.

## Guardian configuration

The agent configuration lives at [Guardian.yaml](Guardian.yaml). It defines:

- **Tasks** — code generation, completion, review, debugging, testing, refactoring, documentation, with per-task confidence thresholds.
- **Guardian agent** — monitors system calls, network connections, and agent interactions; detects threats via machine-learning, signature, anomaly, and behavioral algorithms; assesses the risk of *inaction* (low/medium/high/critical) and escalates at `high`; terminates malicious agents (auto-terminating on `critical` inaction risk) and protects the system by blocking sensitive resource access and preventing system changes.
- **Updates** — threat intelligence from centralized servers, cloud services, peer-to-peer Guardian networks, and local sources; delivered over HTTPS, SFTP, or SSH; as executables, scripts, configs, or database updates.
