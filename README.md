# Rocksoul CLI (`mw-rocksoul-cli`)

Single-binary Go CLI (`rocksoul`) for the MoonWitness Rocksoul AI coding agent ecosystem. Zero external runtime dependencies, zero-config startup, deterministic R0–R4 Risk Tier policy enforcement, and native wire clients for Rocksoul + MoonWitness services.

## Quick Start

```bash
# Build single static binary
CGO_ENABLED=0 go build -o bin/rocksoul ./cmd/rocksoul

# Zero-friction interactive coding chat (no docker compose or login required)
./bin/rocksoul

# Direct one-shot coding task
./bin/rocksoul "explain internal/risk/gate.go"

# Diagnostics & ecosystem probes
./bin/rocksoul doctor
./bin/rocksoul version
```

## Subcommands

- `rocksoul` — launches interactive coding chat immediately in the current directory.
- `rocksoul "<prompt>"` / `rocksoul run <prompt>` — executes a one-shot ReAct coding task wired to the resolved provider and R0–R4 Risk Gate.
- `rocksoul chat` — interactive terminal REPL with `/model`, `/diff`, `/risk`, `/mcp`, `/clear`, `/doctor`, `/plan`, `/act`, `/compact`, `/symbols`, `/help`, `/exit`.
- `rocksoul doctor` — probes `mw-rocksoul-gateway` (`:4510`), `mw-rocksoul-core` (`:4520`), `mw-rocksoul-mcp` (`:4530`), `mw-rocksoul-sandbox` (`:4540`), `mw-rid` (`:4480`), local Ollama (`:11434`), and `git`.
- `rocksoul login` — `mw-rid` OIDC PKCE `S256` flow helper (`--status`, `--start`, `--exchange-code`, `--logout`).
- `rocksoul mcp list` / `rocksoul mcp call <tool> [json]` — discovers and invokes tools on `mw-rocksoul-mcp` (`:4530`).
- `rocksoul init-tui [--target opencode|crush|codex|all]` — generates zero-config `opencode.json`, `.crush.json`, or `.codex/config.toml` pre-wired to `mw-rocksoul-gateway` (`http://127.0.0.1:4510/v1`) and `mw-rocksoul-mcp` (`http://127.0.0.1:4530/mcp`).
- `rocksoul version` — prints build metadata.

## Zero-Fork OpenCode Plugin (`plugins/opencode-rocksoul`)

`plugins/opencode-rocksoul` provides OpenCode hooks (`tool.execute.before` and `chat.headers`) with zero `@moonwitness/orm-*` imports and zero `any` types:
- Evaluates tool executions against `mw-rocksoul-core` (`http://127.0.0.1:4520/v1/risk/evaluate`) with fail-closed R0–R4 enforcement and local hard-blocking for `.githooks/*`, `.env`, `CODEOWNERS`, release governance files, and destructive shell commands.
- Injects `Authorization: Bearer <token>` from `mw-rid` (`ROCKSOUL_TOKEN`, `MW_RID_ACCESS_TOKEN`, or `~/.rocksoul/token.json`).

## Zero-Config Provider Auto-Fallback

When `provider` is `auto` (default), `rocksoul` selects the first available backend:

1. `mw-rocksoul-gateway` (`http://127.0.0.1:4510` / `ROCKSOUL_GATEWAY_URL`)
2. `OPENAI_API_KEY` (`OPENAI_BASE_URL`, `OPENAI_MODEL`)
3. `ANTHROPIC_API_KEY` (`ANTHROPIC_BASE_URL`, `ANTHROPIC_MODEL`, via native `/v1/messages` adapter)
4. `GEMINI_API_KEY` / `GOOGLE_API_KEY` (`GEMINI_MODEL`)
5. Local Ollama (`http://127.0.0.1:11434` / `OLLAMA_HOST`, auto-selecting installed coding models)

Preferences (`/model`, `/risk tier`) persist automatically to `~/.rocksoul/config.json`. Setting `--classification local_only` strictly skips cloud API keys.

## R0–R4 Risk Tier Gate (`internal/risk`)

| Tier | Category | Default Policy |
| --- | --- | --- |
| `R0` | Auto-read (`read_file`, `list_dir`, `grep_search`, `search_symbols`) | Auto-approved |
| `R1` | Local write (`write_file`, `edit_file`) | Approval required (or `--max-tier R1`) |
| `R2` | Local exec (`run_shell`, `sandbox_exec`) | Approval required (or `--max-tier R2`) |
| `R3` | Remote/egress (`mcp_call`, `curl`, `git push`) | Approval required (or `--max-tier R3`) |
| `R4` | Destructive/protected (`.githooks/*`, `.env`, `*.pem`, `rm -rf`, `git reset --hard`) | **Blocked by default**; never auto-approved; requires scoped single-use HMAC approval token |

## Verification

```bash
go vet ./...
go test -count=1 ./...
CGO_ENABLED=0 go build -o bin/rocksoul.exe ./cmd/rocksoul
./bin/rocksoul.exe version
bun test plugins/opencode-rocksoul/tests/plugin.test.ts
```
