![CVE Signal logo](./assets/cve-signal.png)

# CVE-SIGNAL

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Telegram](https://img.shields.io/badge/Alerts-Telegram-26A5E4?logo=telegram&logoColor=white)](https://core.telegram.org/bots/api)
[![CVE Signal](https://github.com/K0NGR3SS/cve-signal/actions/workflows/cve-signal.yml/badge.svg)](https://github.com/K0NGR3SS/cve-signal/actions/workflows/cve-signal.yml)

A lightweight Python pipeline that monitors new high-severity web and cloud CVEs, looks for relevant public exploit references, and sends useful alerts to Telegram.

I built this pipeline for personal use, but its severity thresholds, CWE filters, technology keywords, vulnerability criteria, and exclusions can all be tailored to your own needs, feel free to fork it and edit to your own needs, customization options are listed below.

## What it does

Every three hours, GitHub Actions:

1. Fetches recently published or updated CVEs from the NVD.
2. Filters them by CVSS score, CWE, cloud/web technology, and configurable keywords.
3. Searches NVD references, Exploit-DB metadata, and public GitHub repositories for possible exploit or PoC matches.
4. Ranks up to five matches and sends the result to Telegram.
5. Saves notification state so the same CVE is not sent twice.

If nothing relevant is found, no Telegram message is sent. The project only links to public exploit metadata and repositories; it does not download or execute exploit code.

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
- Cloud providers and web technologies.
- Vulnerability keywords and CWE identifiers.
- Excluded terms and number of exploit matches.

## Run locally

Python 3.11 or newer is required. The project currently uses only the Python standard library.

```bash
PYTHONPATH=src python -m cve_signal --dry-run
```

Useful options:

```bash
PYTHONPATH=src python -m cve_signal --since-hours 3 --dry-run
PYTHONPATH=src python -m unittest discover -s tests -v
```

Set `NVD_API_KEY`, `TELEGRAM_BOT_TOKEN`, and `TELEGRAM_CHAT_ID` as environment variables before a live local run. Never commit them.

## Optional LLM enrichment

The current matcher is deterministic: it uses CVE IDs, source tags, product terms, vulnerability metadata, and repository names/descriptions. LLM could be added to better analyze the web and find better exploit matches and suggestions.
