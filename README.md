# Shaidra

Deep web vulnerability scanner CLI. Shaidra orchestrates battle-tested recon and
scanning tools into one parallel pipeline with a live terminal UI.

> **Authorized testing only.** Use Shaidra solely against systems you own or have
> explicit written permission to test (bug bounty scope, lab ranges, engagements).
> You are responsible for your traffic.

## Features

- Parallel `asyncio` pipeline with nmap-style real-time output
- 11 scan categories selectable with `--categories`
- Scope enforcement: discovered hosts outside your scope file are skipped from
  active scanning
- Rate limiting (default 40 req/s) that auto-lowers when a WAF is detected
- Graceful degradation: a missing external tool skips its stage instead of
  crashing the run
- Non-destructive by default: SQL injection probing runs in detection-only mode
- No files are written unless you pass an `-o` report flag

## Requirements

- Python 3.11+
- Optional external tools (installed and on `PATH`). Missing tools are skipped:
  `subfinder`, `assetfinder`, `httpx`, `naabu`, `katana`, `nuclei`, `dalfox`,
  `sqlmap`, `ffuf`, `feroxbuster`, `wpscan`, `testssl.sh`, `kiterunner`,
  `gowitness`, `wafw00f`, `whatweb`, `jwt_tool`, `subjack`, `gau`,
  `waybackurls`.

## Install

```bash
pip install -e .
# or
pipx install .
```

This installs the `shaidra` console script.

## Usage

```bash
shaidra <target>
shaidra example.com
shaidra http://192.0.2.10:8080
shaidra https://example.com --scope scope.txt --categories recon,webvuln,cve
```

By default Shaidra prints findings to the terminal and writes nothing to disk.

### Reports

Report files are written **only** when requested:

| Flag | Output |
|------|--------|
| `-oJ` | JSON report |
| `-oM` | Markdown report |
| `-oT` | Plain-text report |
| `-oA` | All three formats |

```bash
shaidra example.com -oJ                 # one JSON file
shaidra example.com -oA                 # json + markdown + txt
shaidra example.com -oJ -oM -oA         # formats combine
shaidra example.com -oJ --output-dir out --output-name my-run
```

### Options

| Option | Description |
|--------|-------------|
| `-s, --scope FILE` | Scope file: one domain, wildcard, IP, or CIDR per line |
| `-c, --categories LIST` | Comma-separated categories (default: all) |
| `-r, --rate-limit N` | Requests per second (default: 40) |
| `--threads N` | Concurrency for fuzzing tools |
| `-m, --mode MODE` | `quick` or `deep` |
| `-x, --extended` | Enable heavy checks (screenshots, full wordlists) |
| `--config FILE` | Path to a `config.yaml` |
| `-v, --verbose` | Show discovered hosts and extra detail |
| `-q, --quiet` | Suppress live output |
| `-o, --output FMT` | Report format(s): `J`, `M`, `T`, `A` (repeatable) |
| `--output-dir DIR` | Directory for report files |
| `--output-name NAME` | Base name for report files |
| `--version` | Show the version and exit |

## Categories

`recon`, `takeover`, `content`, `webvuln`, `cors`, `redirect`, `jwt`, `api`,
`cms`, `misconfig`, `cve`.

## Configuration

Configuration resolves in this order (first found wins):

1. `--config PATH`
2. `$SHAIDRA_CONFIG`
3. `./config.yaml`
4. the `config.yaml` shipped with the package

Every key is optional and falls back to the built-in defaults. Never put
credentials in `config.yaml`; read secrets from environment variables.

## Safety guardrails

- Discovery results outside your scope file are excluded from active scanning.
- The rate limit defaults to 40 req/s and is halved automatically when a WAF is
  detected.
- SQL injection checks run in detection-only mode (`--batch --level=1 --risk=1`);
  Shaidra never dumps data or writes to a target.
- `wpscan` runs only when WordPress is detected; `gowitness` and full wordlists
  run only with `--extended`.

## License

MIT
