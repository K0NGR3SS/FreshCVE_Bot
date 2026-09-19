![CVE Signal logo](./assets/cve-signal.png)

# CVE-SIGNAL

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Telegram](https://img.shields.io/badge/Alerts-Telegram-26A5E4?logo=telegram&logoColor=white)](https://core.telegram.org/bots/api)
[![CVE Signal](https://github.com/K0NGR3SS/FreshCVE_Bot/actions/workflows/cve-signal.yml/badge.svg)](https://github.com/K0NGR3SS/FreshCVE_Bot/actions/workflows/cve-signal.yml)

A lightweight Python pipeline that monitors high-severity web and cloud CVEs, ranks public exploit evidence, enriches risk with CISA KEV and EPSS, and sends concise alerts to Telegram.

I built this pipeline for personal use, but its severity thresholds, CWE filters, technology keywords, vulnerability criteria, and exclusions can all be tailored to your own needs, feel free to fork it and edit to your own needs, customization options are listed below.

## What it does

Every three hours, GitHub Actions:

1. Fetches recently published or updated CVEs from NVD and newly added CISA KEV entries.
2. Filters them by CVSS, KEV status, CWE, cloud/web technology, and configurable keywords.
3. Adds EPSS probability and percentile data.
4. Searches exploit-oriented NVD references, Exploit-DB metadata, and public GitHub repositories.
5. Verifies README-only GitHub hits, rejects generic collections, canonicalizes duplicate URLs, and ranks evidence as confirmed, strong, or possible.
6. Sends a compact Telegram alert and replies to the original alert when new evidence appears.
7. Rechecks monitored CVEs for up to 30 days, using a faster schedule during the first 48 hours.

An initial CVE alert can report that no public exploit was found yet. Source failures and rate limits are shown separately from a successful search with no results. Monitored CVEs remain eligible for delayed PoC follow-ups until `monitoring_days` expires.

The project only reads public metadata and README content. It does not download or execute exploit code. GitHub results are explicitly labelled as unverified and should be reviewed before use.

## Evidence confidence

- **Confirmed**: an exact, verified association such as a directly tagged CVE exploit reference or verified Exploit-DB record.
- **Strong**: an exact CVE association from a credible source or dedicated GitHub repository.
- **Possible**: corroborated heuristic evidence, including verified README content or product/vulnerability-class matching.

Product name overlap alone is not accepted as exploit evidence. Internal ranking scores are available with `--explain`, but the alert uses the evidence class because the score is not a calibrated probability.

## Use it yourself

Fork this repository, then open:

```text
Settings → Secrets and variables → Actions
```

Add these repository secrets:

| Secret | Purpose |
| --- | --- |
| `NVD_API_KEY` | Recommended API key from the [NVD](https://nvd.nist.gov/developers/request-an-api-key). |
| `TELEGRAM_BOT_TOKEN` | Token created through [@BotFather](https://t.me/BotFather). |
| `TELEGRAM_CHAT_ID` | Your public channel username or private channel numeric ID. |

The GitHub PoC search uses the short-lived, read-only `GITHUB_TOKEN` created automatically by GitHub Actions. You do not need to create another GitHub secret.

Enable Actions in your fork and run the **CVE Signal** workflow manually with `dry_run` enabled. Once the output looks right, run it with `dry_run` disabled. Scheduled runs then execute every three hours.

Edit [`config.toml`](config.toml) to change:

- CVSS range and maximum CVE age.
- Monitoring duration and early/later recheck intervals.
- Cloud providers and web technologies.
- Vulnerability keywords and CWE identifiers.
- Excluded terms, per-run CVE budget, number of exploit matches, GitHub candidate count, and README verification budget.
- NVD, Exploit-DB, EPSS, and CISA KEV feed URLs.

## Run locally

Python 3.11 or newer is required. The project currently uses only the Python standard library.

```bash
PYTHONPATH=src python -m cve_signal --dry-run
```

Useful options:

```bash
PYTHONPATH=src python -m cve_signal --since-hours 3 --dry-run
PYTHONPATH=src python -m cve_signal --cve CVE-2026-12345 --dry-run --format text --explain
PYTHONPATH=src python -m cve_signal --cve CVE-2026-12345 --dry-run --format json
PYTHONPATH=src python -m cve_signal --sources
PYTHONPATH=src python -m unittest discover -s tests -v
```

Dry-run formats are `telegram-html`, `text`, and newline-delimited `json`. Dry runs use an in-memory state database and do not change scheduled monitoring state. `--cve` bypasses the configured interest filter for targeted inspection but is intentionally restricted to dry-run mode.

Set `NVD_API_KEY`, `TELEGRAM_BOT_TOKEN`, and `TELEGRAM_CHAT_ID` as environment variables before a live local run. Never commit them.

## Matching approach

The matcher is deterministic and evidence-first. It uses exact CVE identifiers, NVD source tags, recognized exploit hosts, Exploit-DB verification metadata, product/version and vulnerability-class corroboration, and GitHub repository and README metadata. An LLM can be added later for summarization, but it should not be the authority that upgrades a candidate to confirmed evidence.

Notification and monitoring state is stored in `data/state.sqlite3`. Existing databases are migrated automatically. The GitHub Actions workflow restores and saves this database between scheduled runs.
