# Flare CI Check

The CI/CD companion to [Flare](https://lab.krismccabe.com/flare/), Kris McCabe's AI-stack exposure checker. Same data source (OSV.dev) and the same severity math (CVSS v3.1 base score, ported straight from Flare's own snapshot generator), but instead of a curated watchlist it scans whatever dependency manifest you point it at, and fails your build on a critical or actively-exploited (CISA KEV) match.

Standalone and dependency-free: `flare_check.py` uses only the Python standard library, so there's no `pip install` step and nothing to keep patched beyond Python itself.

## Use it as a GitHub Action

```yaml
name: Dependency check
on: [pull_request]

jobs:
  flare-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: krismccabe87/kris-lab/flare/ci-action@main
        with:
          severity-threshold: CRITICAL
          fail-on-kev: 'true'
          sarif: flare.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: flare.sarif
```

Pin `@main` to a specific commit SHA (or a tag, once one exists) for a reproducible build - `@main` always tracks the latest version of the check.

### Inputs

| Input | Default | Description |
|---|---|---|
| `files` | *(auto-detect)* | Space-separated manifest paths. Auto-detects `requirements.txt`, `package.json`, `package-lock.json`, `pyproject.toml` in `working-directory` if omitted. |
| `severity-threshold` | `CRITICAL` | Fail the build on any match at or above this severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `fail-on-kev` | `true` | Fail on any CISA KEV (actively exploited) match regardless of `severity-threshold` - an actively exploited advisory is worth stopping on even at a lower CVSS score. |
| `sarif` | *(none)* | Path to write a SARIF 2.1.0 file for GitHub code scanning (or any SARIF-reading tool). |
| `working-directory` | `.` | Directory to run the scan from. |

### Outputs

| Output | Description |
|---|---|
| `result` | `pass` or `fail` |

## Use it directly

No Action needed - `flare_check.py` runs standalone anywhere Python 3 is available:

```bash
python3 flare_check.py --file requirements.txt --sarif flare.sarif --json flare.json
echo "exit code: $?"
```

```
$ python3 flare_check.py --file requirements.txt
Scanning 3 package(s) from: requirements.txt
CRITICAL  litellm    GHSA-r75f-5x8p-qvmc  [ACTIVELY EXPLOITED]  LiteLLM has SQL Injection in Proxy API key verification
...
74 total advisories, 8 at/above CRITICAL, 4 actively exploited (KEV).
RESULT: FAIL
```

Exit codes: `0` = pass, `1` = fail (a match at/above the threshold, or a KEV match), `2` = couldn't run the check at all (no manifest found, a named `--file` doesn't exist, or OSV.dev was unreachable) - a config/infra problem, deliberately distinct from a real "fail" so your pipeline doesn't confuse "we couldn't check" with "we checked and it's clean."

Run `python3 flare_check.py --help` for the full flag list.

## What it checks, and what it doesn't

- **Ecosystems**: PyPI and npm, parsed from `requirements.txt`, `pyproject.toml` (best-effort regex, no `[dependency-groups]`/lockfile-specific resolution), `package.json`, and `package-lock.json`. Other ecosystems (Go, Maven, crates.io, RubyGems, NuGet, Packagist) aren't parsed by the built-in manifest readers - pass exact package names with `--file` pointed at your own pre-extracted list, or open an issue.
- **Matching is by package name, not resolved version.** Like Flare's own live check, this asks "does OSV.dev have *any* advisory for this package" rather than pinning to your exact locked version - broader recall, at the cost of occasionally flagging an advisory your locked version doesn't actually contain. The version ranges Flare/OSV.dev *do* have are always shown in the advisory's own `affected` data if you need to check by hand; this tool doesn't currently filter by them.
- **Severity** comes from OSV's own `database_specific.severity` when present, otherwise a CVSS v3/v4 vector parsed with the same math `flare/src/refresh-signals.py` uses for the live dashboard - the two should never disagree on the same CVE.
- **KEV** is CISA's Known Exploited Vulnerabilities catalog, fetched live from its GitHub mirror on every run. A fetch failure is a warning, not a hard error - the severity check still runs.

## Network calls

Every run calls `api.osv.dev` (always) and `raw.githubusercontent.com` for the CISA KEV catalog (always, to annotate matches - not gated behind `--no-fail-on-kev`, which only changes what affects the exit code). No data about your repository, package versions, or CI environment is sent anywhere else.
