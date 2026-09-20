# OverSeer

## Overview

OEM vulnerability advisories are frequently published before they show up
in NVD or national vulnerability databases, sometimes by days. OverSeer
polls OEM advisory sources directly, filters to Critical/High severity
(CVSS >= 7.0), dedupes against previously seen advisories, and writes
local markdown reports for the ones that pass.

## How it works

Advisories move through four stages, each its own package: `collector/`
adapters pull raw data from a specific OEM source (RSS, a vendor API,
whatever that source exposes) behind a common `fetch()` interface;
`parser/` extracts a CVSS score (from a clean structured field when the
source provides one, otherwise from the advisory text) and filters out
anything below the severity threshold; `storage/` checks a SQLite table
so an advisory already seen isn't re-reported; `notifier/` renders a
Jinja2 markdown report for anything new. `overseer run` drives all four
stages in that order for every registered source. See
[`overseer/daemon/README.md`](overseer/daemon/README.md) for running it
on a schedule (systemd timer or crontab).

- `collector/` — per-OEM adapters implementing `fetch() -> list[RawAdvisory]`
- `parser/` — CVSS extraction and the Critical/High severity gate
- `storage/` — SQLite-backed dedup by advisory ID
- `notifier/` — Jinja2 markdown report generation

## Install

```sh
pipx install git+https://github.com/GT-Snix/OverSeer.git
```

Requires Python 3.11 or later. If your system's default `python3` is
older, `pipx` will fail with `requires a different Python` (or similar) —
point it at a newer interpreter explicitly:

```sh
pipx install --python /path/to/python3.11+ git+https://github.com/GT-Snix/OverSeer.git
```

## Usage

```sh
overseer run
```

Fetches, normalizes, dedupes, stores, and reports on advisories from
every registered source. This is the only command with a working
implementation right now.

```sh
overseer history
overseer config
```

Both are stubs — registered as CLI commands but not yet implemented.
Running either just prints a "not yet implemented" notice.

## Configuration

The Cisco PSIRT source needs OAuth2 client credentials, read from
environment variables:

```sh
export CISCO_CLIENT_ID="..."
export CISCO_CLIENT_SECRET="..."
```

If these aren't set, `overseer run` does not crash. It's designed to
keep going without them: the Cisco source fails cleanly, that failure is
reported in the Source Status table printed at the end of the run, and
every other registered source (currently CISA ICS) still runs normally.
This is intentional — one source being unavailable shouldn't take down
collection from the rest. Example output with credentials unset:

```
                                 Source Status
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Adapter        ┃ Status                                            ┃ Fetched ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
│ CISAICSAdapter │ OK                                                │      30 │
│ CiscoAdapter   │ FAILED - CiscoAdapter is missing required         │       - │
│                │ credentials: CISCO_CLIENT_ID,                     │         │
│                │ CISCO_CLIENT_SECRET. Set them as environment      │         │
│                │ variables (CISCO_CLIENT_ID, CISCO_CLIENT_SECRET)  │         │
│                │ before running `overseer run`.                    │         │
└────────────────┴───────────────────────────────────────────────────┴─────────┘
```

## Troubleshooting

**`pipx install` fails with "requires a different Python"**
Your system's default `python3` is older than 3.11. Point `pipx` at a
newer interpreter explicitly:

```sh
pipx install --python /path/to/python3.11+ git+https://github.com/GT-Snix/OverSeer.git
```

**`overseer: command not found` after a successful `pipx install`**
`pipx`'s bin directory isn't on your `PATH` yet. Run `pipx ensurepath`
and open a new shell (or source your shell's rc file).

**`CiscoAdapter` shows `FAILED` in the Source Status table**
Expected if `CISCO_CLIENT_ID` / `CISCO_CLIENT_SECRET` aren't set — see
Configuration above. The CISA source is unaffected and still runs; only
the Cisco source is skipped for that run.

## Known limitations

- CVSS extraction is regex-based against advisory text for sources
  without a clean structured score field (CISA ICS's RSS feed, for
  example — Cisco's PSIRT API provides a clean numeric field and skips
  this path entirely). It's been verified against real CISA ICS data,
  including advisories that bundle multiple CVEs with multiple CVSS
  vectors each: the extractor takes the maximum score across every
  vector found, including CVSS v4.0 vectors. That said, regex-based
  extraction from prose is inherently less robust than a structured
  field — a source that changes its advisory text format could silently
  break extraction in ways a schema change to a JSON API would not.
- The vendor/product name split for CISA advisories is a heuristic based
  on RSS title structure (first word of the remaining title after the
  advisory ID is stripped out), not a vendor lookup table. It's wrong
  for any title that doesn't follow the common "Vendor Product Name"
  pattern.
- `CiscoAdapter` is built and tested against fixtures matching Cisco's
  documented openVuln API response shape. As of this writing it has
  **not** been confirmed against a live, authenticated call — no Cisco
  API credentials were available during development to verify the real
  response matches the documented shape exactly.
- This is a polling tool on a configurable interval (30 minutes by
  default, via the systemd timer — see
  [`overseer/daemon/README.md`](overseer/daemon/README.md)), not a
  real-time or push-based one. Detection latency is equal to the
  polling interval: an advisory published right after a run will not be
  seen until the next one.

## Development

```sh
pip install -e ".[test]"
pytest
```

23 tests, all passing: adapter-to-`RawAdvisory` mapping for both sources
(`test_cisa_ics.py`, `test_cisco.py`), CVSS normalization and the
Critical/High severity gate — including the multi-vector (max-score) and
CVSS v4.0 regression tests (`test_normalize.py`), SQLite dedup
(`test_db.py`), markdown report rendering (`test_report.py`), and the
full fetch-normalize-dedup-store-report pipeline run end to end against
fixture data (`test_cli_run.py`).

## Current source coverage

- CISA ICS advisories (RSS feed)
- Cisco PSIRT (openVuln API, requires credentials — see Configuration)

This is the current set of registered sources, not an exhaustive list of
what's supported. The adapter interface (`collector/base.py`) is
intentionally source-agnostic; adding another OEM source means writing
one adapter, not changing the parser, storage, or notifier layers.
