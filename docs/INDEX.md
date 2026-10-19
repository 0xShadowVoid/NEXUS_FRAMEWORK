# Documentation Index

Start here. NEXUS documentation is organised for two audiences — **beginners** who need a
guided path, and **expert operators/developers** who need exact references — and every claim is
checked against the repository at version **2.0.2 “Apex”**.

> New to the project? Read the [README](../README.md), then follow the **Beginner path** below.
> Short on time? Use the **task lookup** table.

## Choose your path

| Audience | Read in this order |
|---|---|
| **Complete beginner** | [README](../README.md) → [BEGINNER_GUIDE.md](BEGINNER_GUIDE.md) → [GETTING_STARTED.md](GETTING_STARTED.md) → [INSTALLATION.md](INSTALLATION.md) → [NEXUS_FIRST_RUN_CHECKLIST.md](NEXUS_FIRST_RUN_CHECKLIST.md) → [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| **Security analyst / operator** | [README](../README.md) → [SECURITY.md](SECURITY.md) → [SECURITY_MODEL.md](SECURITY_MODEL.md) → [CONFIGURATION.md](CONFIGURATION.md) → [CLI_REFERENCE.md](CLI_REFERENCE.md) → [WORKFLOWS.md](WORKFLOWS.md) → [PHASES.md](PHASES.md) → [REPORTS_AND_DATABASE.md](REPORTS_AND_DATABASE.md) |
| **Developer / maintainer** | [ARCHITECTURE.md](ARCHITECTURE.md) → [TESTING.md](TESTING.md) → [CONTRIBUTING.md](CONTRIBUTING.md) → [PHASES.md](PHASES.md) → [SUPPORT_STATUS.md](SUPPORT_STATUS.md) → [NEXUS_DEPENDENCY_MATRIX.md](NEXUS_DEPENDENCY_MATRIX.md) |
| **Reviewer / auditor** | [SECURITY_MODEL.md](SECURITY_MODEL.md) → [SUPPORT_STATUS.md](SUPPORT_STATUS.md) → [RELEASE_READINESS.md](RELEASE_READINESS.md) → [releases/NEXUS_STABILITY_REPORT.md](releases/NEXUS_STABILITY_REPORT.md) → [TESTING.md](TESTING.md) |

## Task lookup

| I want to… | Go to |
|---|---|
| Install from source, wheel, Docker, or offline | [INSTALLATION.md](INSTALLATION.md) |
| Verify an install and fix a mixed environment | [NEXUS_FIRST_RUN_CHECKLIST.md](NEXUS_FIRST_RUN_CHECKLIST.md), [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| Configure a target and its scope safely | [CONFIGURATION.md](CONFIGURATION.md), [GETTING_STARTED.md](GETTING_STARTED.md) |
| Find the exact flag for a command | [CLI_REFERENCE.md](CLI_REFERENCE.md) |
| Understand what each phase does | [PHASES.md](PHASES.md) |
| Run recon, batch scans, schedules, or continuous monitoring | [WORKFLOWS.md](WORKFLOWS.md), [EXAMPLES.md](EXAMPLES.md) |
| Read results, query the DB, export SARIF/HTML | [REPORTS_AND_DATABASE.md](REPORTS_AND_DATABASE.md) |
| Drive ZAP, Burp, or Caido | [ADAPTERS.md](ADAPTERS.md) |
| Connect external MCP tool servers | [MCP.md](MCP.md) |
| Enable AI triage or local models | [AI_AND_NEMESIS.md](AI_AND_NEMESIS.md) |
| Understand NEMESIS skills and agents | [nemesis.md](nemesis.md), [SKILLS_REFERENCE.md](SKILLS_REFERENCE.md) |
| Enable secret scanning / pre-commit hooks | [HOOKS.md](HOOKS.md) |
| Operate NEXUS (GUI, backup, recovery) | [NEXUS_OPERATIONS_GUIDE.md](NEXUS_OPERATIONS_GUIDE.md) |
| See which tools are built in vs optional | [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md) |
| Check Python/external dependencies | [NEXUS_DEPENDENCY_MATRIX.md](NEXUS_DEPENDENCY_MATRIX.md) |
| Know what is supported, partial, or unverified | [SUPPORT_STATUS.md](SUPPORT_STATUS.md) |
| Run or write tests | [TESTING.md](TESTING.md) |
| Contribute a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Reference library

### Getting started
- [../README.md](../README.md) — landing page, quick start, documentation map
- [BEGINNER_GUIDE.md](BEGINNER_GUIDE.md) — concepts from zero, tools explained in plain language
- [GETTING_STARTED.md](GETTING_STARTED.md) — step-by-step first authorized scan
- [INSTALLATION.md](INSTALLATION.md) — source, wheel, Docker, clean-venv, offline installs
- [NEXUS_FIRST_RUN_CHECKLIST.md](NEXUS_FIRST_RUN_CHECKLIST.md) — post-install verification

### Using NEXUS
- [CLI_REFERENCE.md](CLI_REFERENCE.md) — all 37 subcommands, shared flags, exit behavior
- [CONFIGURATION.md](CONFIGURATION.md) — every config key, default, and environment variable
- [WORKFLOWS.md](WORKFLOWS.md) — verified end-to-end recipes
- [EXAMPLES.md](EXAMPLES.md) — copy-paste bug-bounty workflows
- [PHASES.md](PHASES.md) — phase registry, gates, execution controls
- [REPORTS_AND_DATABASE.md](REPORTS_AND_DATABASE.md) — results layout, schema, export/backup
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — diagnostics and common failures

### Security and operations
- [SECURITY.md](SECURITY.md) — enforcement matrix and safe-use policy
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — threat model, trust boundaries, residual risks
- [NEXUS_OPERATIONS_GUIDE.md](NEXUS_OPERATIONS_GUIDE.md) — deployment, GUI, backup/recovery
- [HOOKS.md](HOOKS.md) — secret scanning and the pre-commit hook
- [../SECURITY.md](../SECURITY.md) — vulnerability disclosure policy for NEXUS itself

### Integrations
- [ADAPTERS.md](ADAPTERS.md) — ZAP / Burp / Caido adapter contract and limits
- [MCP.md](MCP.md) — MCP client, policy pipeline, transports, limitations
- [AI_AND_NEMESIS.md](AI_AND_NEMESIS.md) — providers, failover, per-agent config, no-AI behavior
- [nemesis.md](nemesis.md) — NEMESIS layer components and safety model
- [SKILLS_REFERENCE.md](SKILLS_REFERENCE.md) — bundled methodology skills
- [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md) — built-in capabilities vs optional binaries
- [NEXUS_DEPENDENCY_MATRIX.md](NEXUS_DEPENDENCY_MATRIX.md) — dependency and browser matrix

### Architecture and development
- [ARCHITECTURE.md](ARCHITECTURE.md) — component/data-flow diagrams, trust boundaries, repo tree
- [TESTING.md](TESTING.md) — test layout, expected results, browser opt-in, CI
- [CONTRIBUTING.md](CONTRIBUTING.md) — conventions, checks, pull-request checklist
- [SUPPORT_STATUS.md](SUPPORT_STATUS.md) — authoritative support and documentation inventory
- [RELEASE_READINESS.md](RELEASE_READINESS.md) — release-readiness evidence
- [releases/NEXUS_STABILITY_REPORT.md](releases/NEXUS_STABILITY_REPORT.md) — stability audit and maintenance policy

### History and planning
- [FEATURE_MAP.md](FEATURE_MAP.md) — feature history and per-row status
- [ROADMAP.md](ROADMAP.md) — historical upgrade plan (not the live status source)

## Canonical sources of truth

When documents disagree, prefer these:

| Question | Authoritative page |
|---|---|
| Is a command/capability supported? | [SUPPORT_STATUS.md](SUPPORT_STATUS.md) |
| What does this flag/key do? | [CLI_REFERENCE.md](CLI_REFERENCE.md) · [CONFIGURATION.md](CONFIGURATION.md) |
| What is enforced in code? | [SECURITY.md](SECURITY.md) · [SECURITY_MODEL.md](SECURITY_MODEL.md) |
| What runs in a scan, and in what order? | [PHASES.md](PHASES.md) · `core/phase_registry.py` |
| What changed / what is planned? | [FEATURE_MAP.md](FEATURE_MAP.md) · [ROADMAP.md](ROADMAP.md) |

## Conventions used here

- **Status words** are deliberate: **supported** (tested), **partial** (documented limits),
  **unverified** (no offline/live evidence), **unavailable** (not implemented).
- Commands are shown for both `python -m nexus` (source checkout) and the installed `nexus`
  script where useful.
- Diagrams use Mermaid and are accompanied by prose so they remain useful without rendering.
- Paths are relative to the repository root unless stated otherwise.
- Examples use `lab.local` / `acme.com` as placeholders. Replace them only with systems you are
  authorized to test.

## Documentation maintenance

Documentation is part of the change, not an afterthought:

1. Update the relevant page in the same pull request as the code.
2. Re-check version strings, defaults, paths, and command flags against the source.
3. Run the link/consistency checks described in [CONTRIBUTING.md](CONTRIBUTING.md).
4. Do not fabricate terminal output; label anything unverified as such.
