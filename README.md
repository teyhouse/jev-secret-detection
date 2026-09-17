# jev-secret-detection

Measures how well TypeSafe's Jev model spots real secret credentials in file snippets. Each test case is sent to
Jev as a single [Noul](https://docs.typesafe.ai/primitives/noul) question ("does `content` contain a real secret
credential that someone reading it could use?"), and the returned probability is compared with the expected label.

There is deliberately no regex matching or provider verification. The goal is to score Jev itself.

## Usage

```bash
echo "TYPESAFE_API_KEY=..." > .env
uv run python main.py
```

The report shows one row per case, then:

- accuracy at a 0.5 threshold
- AUC (how well the scores rank secrets above non-secrets, independent of any threshold)
- how many cases fall in the review band (0.3 to 0.7) versus confident right or wrong
- accuracy per category

## Files

| File | Purpose |
|---|---|
| `main.py` | Runs every case concurrently and prints the report |
| `questions.py` | The Noul question and the pinned model (`jev-1.13.0`) |
| `fixtures.py` | The 100 test cases |
| `utils.py` | Scoring (bands, AUC) and table output |

## Test data

Each case has a `file_path`, the `content` of the snippet, `expected_secret`, and a `category`. Jev receives only
`file_path` and `content`. Case names (`sample_001` and up) are neutral and never sent.

**Labeling rule:** a case is a secret when `content` contains a complete credential value that looks issued or
chosen for real use. The label must be decidable from `content` alone; the path is realistic context, and both
labels appear in docs, example, log, and production files.

The set is split 50/50:

| Secret (50) | Cases | Not a secret (50) | Cases |
|---|---|---|---|
| `vendor_token` (prefixed keys: GitHub, Stripe, Slack, ...) | 14 | `placeholder` (filler, example, or test values) | 16 |
| `embedded_credential` (in code, URLs, headers, logs, CI, k8s) | 13 | `hash_or_id` (SHAs, UUIDs, digests, bcrypt) | 10 |
| `generic_secret` (unprefixed keys named by context) | 9 | `public_value` (public keys, certs, publishable keys) | 9 |
| `password` (configs, connection calls, shell history) | 8 | `redacted` (masked or truncated) | 4 |
| `connection_string` (URIs with embedded passwords) | 3 | `reference` (env vars, secret managers) | 4 |
| `private_key` (EC, ed25519, GCP service account) | 3 | `no_credential` (plain code or config) | 3 |
| | | `encrypted` (SOPS, Ansible Vault) | 2 |
| | | `personal_data` (SSNs, not credentials) | 2 |

Many cases come in pairs that share a value or format but differ in label, for example the same UUID as a
`HEROKU_API_KEY` and as a log correlation ID, or an Algolia admin key next to its search-only key. The comment above
each case explains the label and links its pair. Cases marked "Originally sample_x" come from the first 23-case set,
which drew on gitleaks, GitGuardian, decryptiondigest.com, and cremit.io.

All secret values are randomly generated (key material with openssl and ssh-keygen) and have never been valid
credentials. Expect secret scanners and GitHub push protection to flag `fixtures.py` anyway.
