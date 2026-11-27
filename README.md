# mw-rocksoul-cli — Single-binary command-line client for the Rocksoul AI ecosystem.

**Repository:** [`A-L-L-A-H/mw-rocksoul-cli`](https://github.com/A-L-L-A-H/mw-rocksoul-cli) · **Stack:** Go 1.24 · static binary

## What it does

Runs interactive or one-shot coding tasks through the R0–R4 risk gate, provider fallback, OIDC login, and MCP discovery.

## Quick start

```bash
CGO_ENABLED=0 go build -o bin/rocksoul ./cmd/rocksoul
./bin/rocksoul
```

## Verify

```bash
go vet ./...
go test -count=1 ./...
bun test plugins/opencode-rocksoul/tests/plugin.test.ts
```

## Configuration

- **Key configuration:** Local daemon URLs

```bash
./bin/rocksoul doctor
```

## Notes

The doctor command probes :4510, :4520, :4530, :4540, :4480, Ollama :11434, and git.
