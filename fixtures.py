"""Sample states for the secret-detection Noul test.

Labeling rule: a case is positive when `content` writes out a complete credential value (API key, token,
password, private key, or a URL/header that embeds one) that looks issued or chosen for real use, so
anyone reading the file could use it. Negatives are placeholders and example values, redacted or truncated
values, references to secrets stored elsewhere, encrypted values, public keys and identifiers, hashes and IDs,
code or docs without a value, and personal data that is not a credential. The label must be decidable from
`content`; `file_path` is realistic context only, and both labels appear in docs, example, and prod files.

Every positive value was randomly generated for this file (key material with openssl/ssh-keygen) and has
never been a valid credential. Cases marked 'Originally sample_x' come from the first 23-case set; the three
GitGuardian keyboard-mash examples (old sample_n/o/p) were removed as ambiguous.

Case names are neutral; neither the name nor the category is sent to the model. 'Pair' comments link
cases that share a value or format but differ in label.
"""

from typing import NamedTuple


class Case(NamedTuple):
    file_path: str
    content: str
    expected_secret: bool
    category: str


CASES = {
    # secret: yes - GitHub classic personal access token (ghp_ format, gitleaks github-pat rule). Originally
    # sample_g; the body is now random because the old one ended in the keyboard run 'AsDfGh'. Pair: sample_002.
    "sample_001": Case(
        file_path=".env",
        content="GITHUB_TOKEN=ghp_EzSQ8bZBuYZ1vkmATAmbMbFVdTKuGd8SA15p",
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - Correct ghp_ prefix and length, but the body is all X filler. Pair: sample_001.
    "sample_002": Case(
        file_path="scripts/release.sh",
        content=(
            "#!/usr/bin/env bash\n"
            "export GITHUB_TOKEN=ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"
            'gh release create "$VERSION" dist/*'
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Full GitHub fine-grained token pasted into docs. The value is complete and random, so being in
    # a docs file does not make it an example.
    "sample_003": Case(
        file_path="docs/local-setup.md",
        content=(
            "## Running the sync locally\n"
            "\n"
            "Export a token before starting the worker:\n"
            "\n"
            "    export GH_TOKEN=github_pat_WoB7XcVq6YZrfUZNytEQfZ_rkhp9HiD8VIpzcxMIGTIpYnF8HbrQF05T29FsqSG5g6v"
            "hc2aIOsUj2MldgT\n"
            "    make sync"
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: yes - GitHub token leaked through a debug log line.
    "sample_004": Case(
        file_path="logs/sync-worker.log",
        content=(
            "2026-09-14T08:12:44Z DEBUG http.client send: GET /repos/brightmoor/api/pulls?state=open HTTP/1.1\n"
            "2026-09-14T08:12:44Z DEBUG http.client header: Authorization: token ghp_yt6ifCQxXIe7Oz82vPstzTSX53"
            "X1tz7QB8gR\n"
            "2026-09-14T08:12:45Z DEBUG http.client reply: 200 OK"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: yes - GitLab personal access token (glpat- format).
    "sample_005": Case(
        file_path="scripts/mirror.sh",
        content=(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "export GITLAB_TOKEN=glpat-GDmSf1ltJqPpq4OHjdrj\n"
            'git push --mirror "https://oauth2:${GITLAB_TOKEN}@gitlab.com/brightmoor/platform.git"'
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: yes - Bitbucket app password (ATBB format) embedded in a git remote URL.
    "sample_006": Case(
        file_path=".git/config",
        content=(
            '[remote "origin"]\n'
            "\turl = https://ci-deploy:ATBBXcdOcUHpnYtrE2rv0sBjFDrKaCBdxn4f@bitbucket.org/brightmoor/payments-a"
            "pi.git\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: yes - npm automation token (npm_ format). Pair: sample_008.
    "sample_007": Case(
        file_path=".npmrc",
        content=(
            "registry=https://registry.npmjs.org/\n"
            "//registry.npmjs.org/:_authToken=npm_ZlXscqwC1bhSuY2jk2Spyxsg6mGqfHLDSTLT"
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - Token read from an environment variable, no value. Pair: sample_007.
    "sample_008": Case(
        file_path=".npmrc",
        content=("registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}"),
        expected_secret=False,
        category="reference",
    ),
    # secret: no - Originally sample_m. Allowlist config from decryptiondigest.com (secrets-scanning-pre-commit-
    # ci-enforcement); names placeholder patterns, carries no credential.
    "sample_009": Case(
        file_path=".gitleaks.toml",
        content=('[[allowlist]]\nregexes = ["EXAMPLE_API_KEY", "test_token_.*"]'),
        expected_secret=False,
        category="no_credential",
    ),
    # secret: yes - Originally sample_a. Values regenerated: the old database password 'Tr0ub4dor&3' is the famous
    # xkcd example password. Pairs: sample_011, sample_012, sample_013.
    "sample_010": Case(
        file_path=".env",
        content=(
            "STRIPE_SECRET_KEY=sk_live_516ytSsSWdkKo9ij3hPkKOwbwdN0gKFh9KH9fGsaLLmnF7EaGHnSFb0JOgITDgptnq2q3eMv"
            "rgvHrQMUMqEW1llrbxFqsqlalQc\n"
            "DATABASE_URL=postgres://svc_billing:u7Pofnk2Y11GYGdYqX0dVtTd@prod-db.internal:5432/billing"
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - Live-key prefix with an x filler body, in a production-looking file. Pair: sample_010.
    "sample_011": Case(
        file_path="config/production.env",
        content="STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxxxxxxxxxx",
        expected_secret=False,
        category="placeholder",
    ),
    # secret: no - Masked key, only the last 4 characters visible. Pair: sample_010.
    "sample_012": Case(
        file_path="docs/runbook.md",
        content=(
            "### Payments key rotation\n"
            "\n"
            "Current live key: `sk_live_************************v8nD` (rotated 2026-08-01, owner: payments on-c"
            "all).\n"
            "Rotate it from the Stripe dashboard, then update the value in Vault."
        ),
        expected_secret=False,
        category="redacted",
    ),
    # secret: no - Stripe publishable key: public by design and shipped to browsers. Pair: sample_010.
    "sample_013": Case(
        file_path="web/.env",
        content=(
            "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_51F7dixqqwrCXzTIJ3UvTKU8lRPsyr7tA1dUhbUOu7YjnWXYKKXAmXp"
            "tlM7y0J91yyueU6TMTJndi5SjC2LFuMjt4FK2vyyig2G"
        ),
        expected_secret=False,
        category="public_value",
    ),
    # secret: yes - AWS access key pair in credentials-file format. Pair: sample_015.
    "sample_014": Case(
        file_path="deploy/aws/credentials",
        content=(
            "[default]\n"
            "aws_access_key_id = AKIAVE6QCWRMZ2OHVIK6\n"
            "aws_secret_access_key = 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\n"
            "region = eu-central-1"
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - Originally sample_c. AWS's own documentation key pair (allowlisted by gitleaks); correct
    # format, never functional. Pair: sample_014.
    "sample_015": Case(
        file_path=".env",
        content=(
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Random AWS key pair hardcoded in Terraform. Pair: sample_017.
    "sample_016": Case(
        file_path="infra/main.tf",
        content=(
            'provider "aws" {\n'
            '  region     = "eu-central-1"\n'
            '  access_key = "AKIAEMOM2IJYEQB5NMAK"\n'
            '  secret_key = "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"\n'
            "}"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: no - Originally sample_s. The AWS docs placeholder that cremit.io (secret-scanning-false-positives-
    # causes-and-fixes) calls out, in a Terraform block. Pair: sample_016.
    "sample_017": Case(
        file_path="infra/main.tf",
        content=(
            'provider "aws" {\n'
            '  access_key = "AKIAIOSFODNN7EXAMPLE"\n'
            '  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
            "}"
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Originally sample_k (GCP API key format, from the decryptiondigest.com detector list); body
    # regenerated.
    "sample_018": Case(
        file_path=".env.production",
        content="GOOGLE_API_KEY=AIzaVVHjbd6L4feuq4LuGv9v-F4dUahCAQTjccP",
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - OAuth client ID: a public identifier, no client secret present.
    "sample_019": Case(
        file_path="web/src/auth/config.ts",
        content=(
            "export const googleAuth = {\n"
            '  clientId: "965190178310-b3kq6imsjwhead1ehtfhia6yevvbkx5q.apps.googleusercontent.com",\n'
            '  redirectUri: "https://app.brightmoor.io/auth/callback",\n'
            "};"
        ),
        expected_secret=False,
        category="public_value",
    ),
    # secret: yes - Heroku API keys are UUID-shaped. Pair: sample_022 uses the exact same UUID as a log
    # correlation ID, so only the context separates them.
    "sample_020": Case(
        file_path=".env",
        content="HEROKU_API_KEY=fbc15f39-0e23-482a-a172-a32b62762c30",
        expected_secret=True,
        category="generic_secret",
    ),
    # secret: no - Originally sample_u. A UUID, one of the benign high-entropy categories cremit.io lists (this
    # value is also the Wikipedia UUID example).
    "sample_021": Case(
        file_path="logs/api.log",
        content="request_id=550e8400-e29b-41d4-a716-446655440000",
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: no - Same UUID as sample_020, used as a log correlation ID.
    "sample_022": Case(
        file_path="logs/checkout.log",
        content=(
            "2026-09-15T10:02:31Z INFO checkout.completed order=ORD-88213 correlation_id=fbc15f39-0e23-482a-a17"
            "2-a32b62762c30 duration_ms=412"
        ),
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: yes - Originally sample_h (xoxb- format, gitleaks slack-bot-token rule); body regenerated.
    "sample_023": Case(
        file_path="config/slack.env",
        content="SLACK_BOT_TOKEN=xoxb-1483778967045-9911424100021-QCMxSYR27LvtCMV7WqQuVcfP",
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: yes - Slack incoming webhook URL; anyone holding it can post to the channel.
    "sample_024": Case(
        file_path="monitoring/alertmanager.yml",
        content=(
            "global:\n"
            "  slack_api_url: 'https://hooks.slack.com/services/T6PY6LXB4CY/BE6ENT8PPZ7/UHYvZcVBC3ZY0mVOHd3Uyj3"
            "y'\n"
            "route:\n"
            "  receiver: platform-alerts"
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: yes - Slack user token hardcoded in a workflow. Pair: sample_026.
    "sample_025": Case(
        file_path=".github/workflows/notify.yml",
        content=(
            "name: notify\n"
            "on: [deployment_status]\n"
            "jobs:\n"
            "  slack:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: ./scripts/post-deploy-message.sh\n"
            "        env:\n"
            "          SLACK_TOKEN: xoxp-6485377119947-6940859177528-8545952093675-d3271b831446ed198dcadc6070ba"
            "3d39"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: no - Same workflow reading the token from GitHub secrets. Pair: sample_025.
    "sample_026": Case(
        file_path=".github/workflows/notify.yml",
        content=(
            "name: notify\n"
            "on: [deployment_status]\n"
            "jobs:\n"
            "  slack:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: ./scripts/post-deploy-message.sh\n"
            "        env:\n"
            "          SLACK_TOKEN: ${{ secrets.SLACK_TOKEN }}"
        ),
        expected_secret=False,
        category="reference",
    ),
    # secret: yes - Discord bot token (base64 user id, timestamp, HMAC).
    "sample_027": Case(
        file_path="bot/config.json",
        content=(
            "{\n"
            '  "prefix": "!",\n'
            '  "discord_token": "OTcxMDAzODI4NzQ0MjAxMjU3MA.y5ToPa.RJ8qp7_mpxovkS5n3bp2LHOWGeTIPoO3xoz4zY"'
            "\n"
            "}"
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: yes - Telegram bot token hardcoded in a script.
    "sample_028": Case(
        file_path="alerts/telegram_notify.py",
        content=(
            "import requests\n"
            "\n"
            'TELEGRAM_BOT_TOKEN = "9294936613:AAvK3olPRHWcWoVlw_PriK6elJ42d77mEh2"\n'
            "CHAT_ID = -1001873345120\n"
            "\n"
            "\n"
            "def notify(text: str) -> None:\n"
            '    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"\n'
            '    requests.post(url, json={"chat_id": CHAT_ID, "text": text})'
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: yes - Originally sample_l (Twilio auth token, 32 hex); body regenerated. Pair: sample_030 uses the
    # same 32 hex chars as a cache ETag.
    "sample_029": Case(
        file_path=".env",
        content="TWILIO_AUTH_TOKEN=5c4614d482636023b4e24651b54979aa",
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - Same 32 hex chars as sample_029, used as a content ETag.
    "sample_030": Case(
        file_path="logs/cdn-access.log",
        content=(
            "HTTP/1.1 200 OK\n"
            "Content-Type: image/webp\n"
            'ETag: "5c4614d482636023b4e24651b54979aa"\n'
            "Cache-Control: public, max-age=31536000"
        ),
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: yes - Real-looking SendGrid key committed to an example env file, a common leak. The value decides,
    # not the file name.
    "sample_031": Case(
        file_path=".env.example",
        content=(
            "SENDGRID_API_KEY=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\n"
            "MAIL_FROM=noreply@brightmoor.io"
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: yes - Mailgun API key hardcoded in a request.
    "sample_032": Case(
        file_path="scripts/send_report.py",
        content=(
            "import requests\n"
            "\n"
            "resp = requests.post(\n"
            '    "https://api.mailgun.net/v3/mg.brightmoor.io/messages",\n'
            '    auth=("api", "key-65b34a6705cdbd6e8c9a004b0f38285b"),\n'
            '    data={"from": "reports@brightmoor.io", "to": ["finance@brightmoor.io"], "subject": '
            '"Daily revenue"},\n'
            ")"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: yes - OpenAI project key (sk-proj- format). Pair: sample_034.
    "sample_033": Case(
        file_path="services/assistant/.env",
        content=(
            "OPENAI_API_KEY=sk-proj-AlA9qFgK8-CyaaVbmcLUc5TK5-5GFPs0H9knBx3spbQ-qEqutbN02agLjQPpqw6ph55x1DDVu_T"
            "3BlbkFJP-JZTu3Nr0S31egB4iDVDxpdfrE1A6dbWo1wNxcvX6Lijy5NcIAR56U_zJPtbmZHWZq4z_GyyE"
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - Prefix followed by filler text. Pair: sample_033.
    "sample_034": Case(
        file_path="services/assistant/.env.example",
        content="OPENAI_API_KEY=sk-proj-your-api-key-here",
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Anthropic API key hardcoded in code. Pair: sample_036.
    "sample_035": Case(
        file_path="app/llm.py",
        content=(
            "import anthropic\n"
            "\n"
            'client = anthropic.Anthropic(api_key="sk-ant-api03-DH60XNG1IV8ElMQzcHS4ZujkTlxOx7lSpHhZ1upjS2GW_w'
            'jNxGipOF0DaBwRsr4oLhvajVOJFYVLBgUrHb-s3wtaxnQkjAA")'
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: no - Truncated key as shown in a console listing. Pair: sample_035.
    "sample_036": Case(
        file_path="docs/key-inventory.md",
        content=(
            "| Service | Key | Created | Owner |\n"
            "|---|---|---|---|\n"
            "| Summarizer | sk-ant-api03-lxB...hqAA | 2026-06-02 | ml-platform |"
        ),
        expected_secret=False,
        category="redacted",
    ),
    # secret: yes - Datadog API key (32 hex) in the agent config.
    "sample_037": Case(
        file_path="ops/datadog/datadog.yaml",
        content=("api_key: 8a1b2aa826d30b8783f7b557b29837a2\nsite: datadoghq.eu\nlogs_enabled: true"),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: yes - Django SECRET_KEY in production settings.
    "sample_038": Case(
        file_path="mysite/settings.py",
        content=(
            "DEBUG = False\n"
            'ALLOWED_HOSTS = ["app.brightmoor.io"]\n'
            "SECRET_KEY = 'iuw4_9r=lg1&$*x9d5z(u67bnr6f$oj%gjc4q^w%m@8*)+($$3'"
        ),
        expected_secret=True,
        category="generic_secret",
    ),
    # secret: yes - Rails secret_key_base.
    "sample_039": Case(
        file_path="config/secrets.yml",
        content=(
            "production:\n"
            "  secret_key_base: c5b9b7bc5d90f0ee3cc315e46b51d67356da0216b833322d18bfb81aed16836ffe70c206757e698"
            "fdd3e2c75ab5dd00daa3894c3f0ae726116d606e0ca0f79ef"
        ),
        expected_secret=True,
        category="generic_secret",
    ),
    # secret: yes - JWT signing secret. Pair: sample_041.
    "sample_040": Case(
        file_path="api/.env",
        content="JWT_SECRET=LFVpwt/Acv3hHEBff7z08pu8Bsdx/n1yi7qHfdC1H2YygkpjiDfOfLj3sCDa5OOu",
        expected_secret=True,
        category="generic_secret",
    ),
    # secret: no - jwt.io's default placeholder secret. Pair: sample_040.
    "sample_041": Case(
        file_path="api/config/default.env",
        content="JWT_SECRET=your-256-bit-secret",
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Base64 256-bit data encryption key.
    "sample_042": Case(
        file_path="config/app.yml",
        content=(
            'storage:\n  bucket: brightmoor-invoices\n  encryption_key: "6oWttEh7sYOkNKnfBCcvA5QBbgDsZT5Tek68yits0zM="'
        ),
        expected_secret=True,
        category="generic_secret",
    ),
    # secret: yes - Unprefixed internal API key; the field name gives the context. Pair: sample_044.
    "sample_043": Case(
        file_path="config/services.yml",
        content=(
            "inventory_service:\n"
            "  base_url: http://inventory.brightmoor.internal\n"
            '  api_key: "iauAqrSN4bKNsXHVKTu1C5tRnW7zV3vUOIH3Qw6k"'
        ),
        expected_secret=True,
        category="generic_secret",
    ),
    # secret: no - Template placeholder in the same config. Pair: sample_043.
    "sample_044": Case(
        file_path="config/services.yml",
        content=('inventory_service:\n  base_url: http://inventory.brightmoor.internal\n  api_key: "<YOUR_API_KEY>"'),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: no - Originally sample_r. GitGuardian generic_high_entropy_secret docs example of a value with too
    # little entropy (docs use `secret = ...`); a repeating filler pattern.
    "sample_045": Case(
        file_path="server/config.py",
        content='session_token = "xob1xob1xob1xob1xob1xob1xob1"',
        expected_secret=False,
        category="placeholder",
    ),
    # secret: no - Originally sample_j. Matches the test_token_.* allowlist regex from decryptiondigest.com.
    "sample_046": Case(
        file_path=".env",
        content="AUTH_TOKEN=test_token_9f8a3c2e1b7d4d21",
        expected_secret=False,
        category="placeholder",
    ),
    # secret: no - Originally sample_i. The EXAMPLE_API_KEY placeholder decryptiondigest.com cites as allowlisted.
    "sample_047": Case(
        file_path="config/production.env",
        content="API_KEY=EXAMPLE_API_KEY_REPLACE_ME",
        expected_secret=False,
        category="placeholder",
    ),
    # secret: no - Sequential filler with the right length for a 32-char key.
    "sample_048": Case(
        file_path="app/settings_local.py",
        content='API_KEY = "1234567890abcdef1234567890abcdef"',
        expected_secret=False,
        category="placeholder",
    ),
    # secret: no - Originally sample_d, relabeled from yes to no. gitleaks uses this string in the sidekiq-secret
    # rule's regex self-test (a pattern-match test, not a credential); cafebabe and deadbeef are well-known hex
    # filler words.
    "sample_049": Case(
        file_path="scripts/bundle.sh",
        content="export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef",
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Webhook signing secret. Pair: sample_051 uses the same 40 hex chars as a commit SHA.
    "sample_050": Case(
        file_path=".env",
        content="GITHUB_WEBHOOK_SECRET=8493a3ad585f50ad9bfcdc97feca1c38fc273992",
        expected_secret=True,
        category="generic_secret",
    ),
    # secret: no - Same 40 hex chars as sample_050, used as a commit SHA.
    "sample_051": Case(
        file_path="ci/build.sh",
        content=("git fetch origin\ngit checkout 8493a3ad585f50ad9bfcdc97feca1c38fc273992\nmake build"),
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: no - Originally sample_t. A git SHA (git's well-known empty-tree hash), a benign category from
    # cremit.io.
    "sample_052": Case(
        file_path="ci/build.env",
        content="parent_commit=4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: no - Originally sample_q. GitGuardian generic_high_entropy_secret docs example that is not caught
    # because object_id is not a sensitive name.
    "sample_053": Case(
        file_path="src/storage/objects.py",
        content='object_id = "hj65_klhz/trlupok76"',
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: no - SOPS-encrypted value; unusable without the KMS key.
    "sample_054": Case(
        file_path="secrets/prod.enc.yaml",
        content=(
            "db:\n"
            "    password: ENC[AES256_GCM,data:pGHLFdzamBvt/WiowcoIW7Od,iv:If9EcYr+t5gPWDwYHjmdHkt7V2Wgm7lCI5yy"
            "NT26vxo=,tag:+L5cbLnqEuNQtE7bgnE3MA==,type:str]\n"
            "sops:\n"
            "    kms:\n"
            "        - arn: arn:aws:kms:eu-central-1:817683552920:key/bc4da1a4-d89d-4b79-9b33-7d02efc96f0b"
        ),
        expected_secret=False,
        category="encrypted",
    ),
    # secret: no - Ansible Vault ciphertext; unusable without the vault password.
    "sample_055": Case(
        file_path="ansible/group_vars/prod/vault.yml",
        content=(
            "$ANSIBLE_VAULT;1.1;AES256\n"
            "77b976afc8d8d504d96174dec3190cdc3f6cd5cb41c2d1a5f30a6f44e9a0bda6c056ab6997a6752b\n"
            "89ebe6dc6e717af793055143d010643c6cea4ca615e517965e8f47ba63c64fcbdbb47ea74e0966e3\n"
            "269e43a7b5f8069077f78734fd994edb0976dc502cd2ca444caef0deeec9c5f7ed58530a7dcbce05\n"
            "9a6db822d6bc4e7a9016f1220d7efedd4a312d93a41594bf9788d54a46dfa9295dfc13a7fd8fe52f\n"
            "62eb85f82094f0897279bcb0f7c101790d87a408111af7951c5792434add0bfcfcbdcb7eabef6e4e\n"
            "b538fc2f6c025e810214b37eebb3a251a7b60b5ea449d5"
        ),
        expected_secret=False,
        category="encrypted",
    ),
    # secret: yes - Random database password in compose. Pair: sample_057.
    "sample_056": Case(
        file_path="docker-compose.yml",
        content=(
            "services:\n"
            "  db:\n"
            "    image: postgres:16\n"
            "    environment:\n"
            "      POSTGRES_USER: orders\n"
            '      POSTGRES_PASSWORD: "8CWeVXjtgeg-!8#Z1K_g!u"'
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: no - Default placeholder password. Pair: sample_056.
    "sample_057": Case(
        file_path="docker-compose.yml",
        content=(
            "services:\n"
            "  db:\n"
            "    image: postgres:16\n"
            "    environment:\n"
            "      POSTGRES_USER: orders\n"
            "      POSTGRES_PASSWORD: changeme"
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - PostgreSQL password file entry.
    "sample_058": Case(
        file_path="ops/pgpass",
        content="db-prod-02.brightmoor.internal:5432:orders:orders_svc:HclwUlOT8Y5O%Oy5UQKol*A6",
        expected_secret=True,
        category="password",
    ),
    # secret: yes - Spring datasource password.
    "sample_059": Case(
        file_path="src/main/resources/application-prod.properties",
        content=(
            "spring.datasource.url=jdbc:postgresql://db-prod-02.brightmoor.internal:5432/orders\n"
            "spring.datasource.username=orders_app\n"
            "spring.datasource.password=dFx42VpCtq*^RTYQwEjA"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: yes - Database password hardcoded in a Python connect call.
    "sample_060": Case(
        file_path="etl/load_orders.py",
        content=(
            "import psycopg2\n"
            "\n"
            "conn = psycopg2.connect(\n"
            '    host="db-prod-02.brightmoor.internal",\n'
            '    dbname="orders",\n'
            '    user="etl_loader",\n'
            '    password="cdd7m#iGBj40em#^sPRP",\n'
            ")"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: yes - WordPress database password.
    "sample_061": Case(
        file_path="wp-config.php",
        content=(
            "define( 'DB_NAME', 'brightmoor_wp' );\n"
            "define( 'DB_USER', 'wp_prod' );\n"
            "define( 'DB_PASSWORD', '5ghfZ1%7%l4yB1_F5dSx' );\n"
            "define( 'DB_HOST', 'mysql-01.brightmoor.internal' );"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: yes - Human-chosen passphrase rather than a random string; still a real password.
    "sample_062": Case(
        file_path="mailer/.env",
        content=("SMTP_HOST=smtp.brightmoor.io\nSMTP_USER=notifications\nSMTP_PASSWORD=Lantern-Ridge-Maple-4826"),
        expected_secret=True,
        category="password",
    ),
    # secret: yes - MongoDB URI with an embedded password. Pair: sample_064.
    "sample_063": Case(
        file_path="config/database.js",
        content=(
            'const uri = "mongodb+srv://app_user:Dr23sdYaIB0n3fJ4JPZG6YkV@cluster0.ru7et.mongodb.net/orders?re'
            'tryWrites=true";\n'
            "module.exports = { uri };"
        ),
        expected_secret=True,
        category="connection_string",
    ),
    # secret: no - Same URI with template placeholders. Pair: sample_063.
    "sample_064": Case(
        file_path="config/database.js",
        content=(
            'const uri = "mongodb+srv://<username>:<password>@cluster0.mongodb.net/orders?retryWrites=true";'
            "\n"
            "module.exports = { uri };"
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - RabbitMQ broker URL with an embedded password.
    "sample_065": Case(
        file_path="worker/celeryconfig.py",
        content=(
            'broker_url = "amqp://orders:QAgZ07errqwQLtQ6zHYJMt0g@rabbitmq.brightmoor.internal:5672//"\n'
            'result_backend = "rpc://"'
        ),
        expected_secret=True,
        category="connection_string",
    ),
    # secret: yes - SQL Server connection string with a password.
    "sample_066": Case(
        file_path="appsettings.Production.json",
        content=(
            "{\n"
            '  "ConnectionStrings": {\n'
            '    "Billing": "Server=sql-prod-01.brightmoor.internal;Database=Billing;User Id=billing_app;Pas'
            'sword=1yB!PAmh%jeHxf!jACw1;Encrypt=True;"\n'
            "  }\n"
            "}"
        ),
        expected_secret=True,
        category="connection_string",
    ),
    # secret: no - Config dump with the password masked.
    "sample_067": Case(
        file_path="logs/config-dump.json",
        content=(
            '{"event": "config.loaded", "database": {"host": "db-prod-02.brightmoor.internal", "user'
            '": "billing_app", "password": "***"}, "cache": {"url": "redis://redis-prod.brightmoor.'
            'internal:6379/0"}}'
        ),
        expected_secret=False,
        category="redacted",
    ),
    # secret: no - Password pulled from Vault at plan time, no value.
    "sample_068": Case(
        file_path="infra/rds.tf",
        content=(
            'data "vault_generic_secret" "db" {\n'
            '  path = "secret/prod/orders-db"\n'
            "}\n"
            "\n"
            'resource "aws_db_instance" "orders" {\n'
            '  identifier = "orders-prod"\n'
            '  username   = "orders_admin"\n'
            '  password   = data.vault_generic_secret.db.data["password"]\n'
            "}"
        ),
        expected_secret=False,
        category="reference",
    ),
    # secret: yes - Kubernetes Secret; data values are only base64-encoded, not encrypted. Pair: sample_070.
    "sample_069": Case(
        file_path="k8s/db-secret.yaml",
        content=(
            "apiVersion: v1\n"
            "kind: Secret\n"
            "metadata:\n"
            "  name: db-credentials\n"
            "type: Opaque\n"
            "data:\n"
            "  username: b3JkZXJzX2FwcA==\n"
            "  password: ZXdWKjI2bHJna2VGcjZZdTU1N2VOd1Ro"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: no - Deployment referencing the Secret by name. Pair: sample_069.
    "sample_070": Case(
        file_path="k8s/api-deployment.yaml",
        content=(
            "      containers:\n"
            "        - name: api\n"
            "          image: registry.brightmoor.io/api:2.4.0\n"
            "          env:\n"
            "            - name: DB_PASSWORD\n"
            "              valueFrom:\n"
            "                secretKeyRef:\n"
            "                  name: db-credentials\n"
            "                  key: password"
        ),
        expected_secret=False,
        category="reference",
    ),
    # secret: yes - Docker registry auth: base64 of username and access token.
    "sample_071": Case(
        file_path=".docker/config.json",
        content=(
            "{\n"
            '  "auths": {\n'
            '    "https://index.docker.io/v1/": {\n'
            '      "auth": "YnJpZ2h0bW9vci1jaTpkY2tyX3BhdF9WVV85dnRvM0lzTVo5azdUU1V0TXdNN0UxdTU="\n'
            "    }\n"
            "  }\n"
            "}"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: yes - HTTP Basic auth header: base64 of username and password.
    "sample_072": Case(
        file_path="api-tests/orders.http",
        content=(
            "GET https://api.brightmoor.io/v1/orders?status=open\n"
            "Authorization: Basic cmVwb3J0aW5nOkhXLXloN045V283Yi0jM3hrdWlp\n"
            "Accept: application/json"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: yes - EC private key (generated for this fixture). Pair: sample_074.
    "sample_073": Case(
        file_path="certs/server.key",
        content=(
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEIL+qFC6OXGIurl7PCR8Q04p8dH7RZEQ0CQz5XJMjbdr0oAoGCCqGSM49\n"
            "AwEHoUQDQgAEZ+bpNkebpXwB8OMrdc4ZXOdqDLTwiJeWik68lTKKrbD71avfRBdG\n"
            "R55a6R6WaL4oacL7p96J0PxcJhfoC0J+cw==\n"
            "-----END EC PRIVATE KEY-----"
        ),
        expected_secret=True,
        category="private_key",
    ),
    # secret: no - Public half of sample_073.
    "sample_074": Case(
        file_path="certs/server.pub",
        content=(
            "-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ+bpNkebpXwB8OMrdc4ZXOdqDLTw\n"
            "iJeWik68lTKKrbD71avfRBdGR55a6R6WaL4oacL7p96J0PxcJhfoC0J+cw==\n"
            "-----END PUBLIC KEY-----"
        ),
        expected_secret=False,
        category="public_value",
    ),
    # secret: yes - OpenSSH ed25519 private key (generated for this fixture). Pair: sample_076.
    "sample_075": Case(
        file_path="deploy/keys/id_ed25519",
        content=(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
            "QyNTUxOQAAACBPCeacaWOy5RT5K3INe+bScDtHVFumndYGKvhZts9rAAAAAKBBy+YxQcvm\n"
            "MQAAAAtzc2gtZWQyNTUxOQAAACBPCeacaWOy5RT5K3INe+bScDtHVFumndYGKvhZts9rAA\n"
            "AAAEBy+h5TrDGF+qlJFM0+Az1EtlirVhj3ha4+BOq0tpoN5U8J5pxpY7LlFPkrcg175tJw\n"
            "O0dUW6ad1gYq+Fm2z2sAAAAAFmRlcGxveUBidWlsZC1ydW5uZXItMDIBAgMEBQYH\n"
            "-----END OPENSSH PRIVATE KEY-----"
        ),
        expected_secret=True,
        category="private_key",
    ),
    # secret: no - Public half of sample_075.
    "sample_076": Case(
        file_path="deploy/keys/id_ed25519.pub",
        content=(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE8J5pxpY7LlFPkrcg175tJwO0dUW6ad1gYq+Fm2z2sA deploy@build-runner-02"
        ),
        expected_secret=False,
        category="public_value",
    ),
    # secret: yes - GCP service account key file with an RSA private key (generated for this fixture).
    "sample_077": Case(
        file_path="gcp-service-account.json",
        content=(
            "{\n"
            '  "type": "service_account",\n'
            '  "project_id": "brightmoor-billing-prod",\n'
            '  "private_key_id": "f8f56bee6ac8bf42cb57db0509fbb416ff9fe57e",\n'
            '  "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoI'
            "BAQCippdMosKDrCDn\\nL25zpaQB/yfUCXh5msKcLRYMLyuYvtIOGGsrexG695D9ozKiRp60GnddlLKlO7Y1\\n9p7d0C4oJ4J"
            "SE3MO7xOv7VJDY7zP01qi73s862/Qbr5R5dYJ9kV2T91YAsWsRVaV\\nAO3NfKQu3lACkcT+97qZk8uTPf7h42bCv10B+MmCDn"
            "Sn3ynxKfSFvx+MebNzVrul\\nYldKl9PX1ScfRV4UGBblky7Wmn/3km2SjxUrcSqftEA+o+q/KjLg6H9FngJmfrD9\\nnRUckK"
            "MGMQF16SYPgcXb0hG5CpqDhZO0lnXjqMOlZMk0KNmnwRbo4s8fuTSyMwca\\nJNJUhdiHAgMBAAECggEAAxZO81TyYDLxywbex"
            "qwbCIXoIsMCfnlVysB/LcaAL+gx\\nk4MakRA67jURGXGclRXSP2o1YBMk1FLNJkaVGhywY5ZXDdcukbJHydsjAN3Gtgq7\\ns"
            "J9AiuUV2uMDyY9MElZt0cEnc2dWQbpU5qgPeeZRiuBJV1b0AKG+Ul/pMPnIW0NM\\n3DlFSO1s/EviFQpHw9S7vo+oDfTwMNOz"
            "T2gfQGVBml6TjwTMq8octPnNziakOy8+\\nbOR+22p8EKhWS+QwVapUe2/wUkpD+d5FNDzTREqhSjtAnTo3LQ9KfInakkTms1A"
            "U\\nPOJBy+MztMlIa3FSL4K6roPYyLpWEG+mv7W2CA02YQKBgQDd5XS3rc4B4KYJ2muL\\njQgQwdyFhWo8egzD7GKO0N4p26Q"
            "6eS7pXZIQXAd5IpZMVwhi8Tj/HeNuFsAljvDy\\nwbvXJ0TBDsuXc0Kz1+JoWIsyvWuFa7TAM9HAnZGsXAmpYW0jKdn7lS5ZPG"
            "fjyyH1\\nr9x46qJZ9/qld4F6RtBLB7T8qQKBgQC7phv7BRcedVgNKHq5iMfLw0N/IxmlaoXb\\nkHcDgNBmlASBV4PAnxjE4z"
            "DHpZO3EEVsMTWP2Rn3UQeHII5UECtfiUwFulZF9NR+\\ndsA+0CzSy27phs9GbmDepWCWJJC09I9tgHE1rPZBfK28qywwI/Za5"
            "mMtR7eYXGLi\\noUs7ft+5rwKBgQDMS/1JO7FnEyFsAvhvVJqvav2QxUQJiEmGfXZEjVNucHXlDDu/\\nylG31DNhORHuGVd0W"
            "Smj4S3K5xFjwxZeOzapodLweKHDv/ASytn+Pj9yqOl8vqx9\\nJXiiAbDkYxzWIQgtjtPOiQxSRoZUOWr73D196nEtql3PyJai"
            "MN6HpgHheQKBgF4Y\\nUomSKOCmGOwoMzocA4wCszLqh+6xtsO98l/4VQhLCuNM3g1V+haokgpa1fKDHzy8\\nhE5IoEOrBypU"
            "QeqXXRiAAXYR1TcpKPDtXUNiIkflqQ1DA2ce7EZZCVDgrwt+YvmW\\n4a33uFhoS7qC3xqYve0g//RxtPeaxB8+oDoKSeeTAoG"
            "AWz7dwmz3pW/sUFWl9Tib\\nwVJJkLHNsQsXbyFnnYN3wf7AEK16ELnXIur4dF4rtw93qjs85fP6aHgbT9o23XyZ\\nHUwJphc"
            "kdt+Iw1RdPM9OCKi+WSntSnsCJp8upfLGsqFDBJh70ry1HlwM+8Rb83lf\\nHeTkWYEey+YEPjwQRX4+bSQ=\\n-----END PR"
            'IVATE KEY-----\\n",\n'
            '  "client_email": "billing-exporter@brightmoor-billing-prod.iam.gserviceaccount.com",\n'
            '  "client_id": "361150420465429156915",\n'
            '  "token_uri": "https://oauth2.googleapis.com/token"\n'
            "}"
        ),
        expected_secret=True,
        category="private_key",
    ),
    # secret: no - PEM armor around a placeholder. Pair: sample_073.
    "sample_078": Case(
        file_path="certs/README.md",
        content=(
            "Place the TLS key at `certs/server.key` in this format:\n"
            "\n"
            "-----BEGIN EC PRIVATE KEY-----\n"
            "<paste your private key here>\n"
            "-----END EC PRIVATE KEY-----"
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Signed JWT bearer token hardcoded in a smoke test. Pair: sample_080.
    "sample_079": Case(
        file_path="scripts/smoke_test.sh",
        content=(
            "#!/usr/bin/env bash\n"
            "curl -sf https://api.brightmoor.io/v1/orders?limit=1 \\\n"
            '  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtcmVwb3J0aW5nIiwi'
            "c2NvcGUiOiJvcmRlcnM6cmVhZCBvcmRlcnM6d3JpdGUiLCJpYXQiOjE3ODgxMzQ0MDB9.3A341_9U5ucC38LozPOexdQBqgRn1"
            '882voJcwzaViYE" \\\n'
            '  -H "Accept: application/json"'
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: no - Bearer token redacted by the logger. Pair: sample_079.
    "sample_080": Case(
        file_path="logs/gateway.log",
        content=(
            '2026-09-15T09:41:07Z INFO request method=GET path=/v1/orders status=200 headers={"Authorization"'
            ': "Bearer [REDACTED]", "User-Agent": "reporting-job/1.3"}'
        ),
        expected_secret=False,
        category="redacted",
    ),
    # secret: no - Originally sample_b. Ordinary code.
    "sample_081": Case(
        file_path="src/math_utils.py",
        content=(
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n"
            "\n"
            "# TODO: add unit tests for this function before the next release"
        ),
        expected_secret=False,
        category="no_credential",
    ),
    # secret: no - Code that generates keys at runtime; no key value.
    "sample_082": Case(
        file_path="auth/tokens.py",
        content=('import secrets\n\n\ndef new_api_key() -> str:\n    return "bm_" + secrets.token_urlsafe(32)'),
        expected_secret=False,
        category="no_credential",
    ),
    # secret: no - Originally sample_e. SSN test value from the gitleaks README allowlist example. Personal data,
    # not a credential.
    "sample_083": Case(
        file_path="data/customer_record.txt",
        content="customer_ssn=219-09-9999",
        expected_secret=False,
        category="personal_data",
    ),
    # secret: no - Originally sample_f. The 1938 Woolworth wallet specimen SSN, also in the gitleaks README
    # allowlist example.
    "sample_084": Case(
        file_path="data/customer_record.txt",
        content="ssn_on_file=078-05-1120",
        expected_secret=False,
        category="personal_data",
    ),
    # secret: no - Originally sample_v. Base64 image fragment, a benign category from cremit.io.
    "sample_085": Case(
        file_path="web/src/components/avatar.css",
        content=(
            "thumbnail=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQ"
            "UBAScY42YAAAAASUVORK5CYII="
        ),
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: no - Originally sample_w. Lockfile integrity hash, a benign category from cremit.io.
    "sample_086": Case(
        file_path="package-lock.json",
        content=(
            '"integrity": "sha512-1qWnhF/BAAWVzXWVWMKb9Zto/eKwGyGkAJKA0v5oXKG4xZKxJp/nq1PISvKzHKQMHbAADkeVUQ'
            'BBv+LuBAT7XA=="'
        ),
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: no - Container image pinned by digest.
    "sample_087": Case(
        file_path="k8s/nginx-deployment.yaml",
        content=(
            "      containers:\n"
            "        - name: nginx\n"
            "          image: nginx@sha256:7730e89180eb354fefef294131a0db10bc783deb45d0dc3c0063a092a4e01572"
        ),
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: no - Public blockchain address; receiving funds needs no secret.
    "sample_088": Case(
        file_path="config/treasury.env",
        content="TREASURY_WALLET_ADDRESS=0x24a05055ad5dbc32dd1b86bbc2c39e42f250823f",
        expected_secret=False,
        category="public_value",
    ),
    # secret: yes - Algolia admin key: full write access to the index. Pair: sample_090.
    "sample_089": Case(
        file_path="search/.env",
        content=("ALGOLIA_APP_ID=PJB3QIESSP\nALGOLIA_ADMIN_API_KEY=3383d9f013b6332a86ae3cf22118b967"),
        expected_secret=True,
        category="generic_secret",
    ),
    # secret: no - Search-only key, same 32-hex format as sample_089, public by design.
    "sample_090": Case(
        file_path="web/src/search.ts",
        content=(
            'export const search = algoliasearch("PJB3QIESSP", "0ff7158ff3bf2d8c1bb56cbe43211c43"); // sear'
            "ch-only key, safe in the browser"
        ),
        expected_secret=False,
        category="public_value",
    ),
    # secret: yes - reCAPTCHA secret key for server-side verification. Pair: sample_092.
    "sample_091": Case(
        file_path=".env",
        content="RECAPTCHA_SECRET_KEY=6Lf0FQnse52RtA9ziohCFZUX0hozX_29W0W2uj1h",
        expected_secret=True,
        category="generic_secret",
    ),
    # secret: no - reCAPTCHA site key, embedded in public HTML. Same format as sample_091.
    "sample_092": Case(
        file_path="web/templates/signup.html",
        content=(
            '<form method="post" action="/signup">\n'
            '  <div class="g-recaptcha" data-sitekey="6L4qh_G3JzMCq4aJVrIvmO_nKNTrxhjPyExYnTrr"></div>\n'
            '  <button type="submit">Create account</button>\n'
            "</form>"
        ),
        expected_secret=False,
        category="public_value",
    ),
    # secret: yes - Logged-in session cookie pasted into a support ticket; it can hijack the session.
    "sample_093": Case(
        file_path="support/ticket-4812-headers.txt",
        content=(
            ":authority: app.brightmoor.io\n"
            ":method: GET\n"
            ":path: /account/billing\n"
            "cookie: _bm_session=pXB7_HGfrYlPGj08cldYmxEW2vAiMiurwwd6AUVK2XmS5wyAf4SBDTx3CW1w07iU; locale=en-GB"
            "\n"
            "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: yes - API key passed in a URL query string and captured by the access log.
    "sample_094": Case(
        file_path="logs/nginx/access.log",
        content=(
            '10.20.4.17 - - [15/Sep/2026:11:02:44 +0000] "GET /v1/export?format=csv&api_key=hONAS4jiXJqCNBB2fA'
            'Um4nRCEj5kyKDAxKC8haWx HTTP/1.1" 200 48213'
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: yes - Database password stored in plain text in Terraform state.
    "sample_095": Case(
        file_path="terraform.tfstate",
        content=(
            "{\n"
            '  "type": "aws_db_instance",\n'
            '  "name": "orders",\n'
            '  "instances": [\n'
            "    {\n"
            '      "attributes": {\n'
            '        "identifier": "orders-prod",\n'
            '        "username": "orders_admin",\n'
            '        "password": "yldjw-pS6yM3HQ^A18eEov^a"\n'
            "      }\n"
            "    }\n"
            "  ]\n"
            "}"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: yes - Password typed on the command line and saved in shell history.
    "sample_096": Case(
        file_path=".bash_history",
        content=(
            "cd /srv/orders\nmysql -h db-prod-02.brightmoor.internal -u root -p'a35ssyrUEzIb1+zp5XjW' orders\nexit"
        ),
        expected_secret=True,
        category="password",
    ),
    # secret: no - bcrypt password hash; the password itself is not recoverable from it.
    "sample_097": Case(
        file_path="ops/.htpasswd",
        content="ops-dashboard:$2y$10$1BWcKZ6gfE0bNvpt03f8kfzRmLg/PmtQLAZNYt04.b/zrN4H9kPrd",
        expected_secret=False,
        category="hash_or_id",
    ),
    # secret: no - Self-signed X.509 certificate for sample_073; certificates are public.
    "sample_098": Case(
        file_path="certs/server.crt",
        content=(
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBmDCCAT+gAwIBAgIUf7z9VVA0BoVDh4G2uGyMBrrzXzswCgYIKoZIzj0EAwIw\n"
            "IjEgMB4GA1UEAwwXYXBpLmJyaWdodG1vb3IuaW50ZXJuYWwwHhcNMjYwOTE3MTEw\n"
            "NDQyWhcNMjcwOTE3MTEwNDQyWjAiMSAwHgYDVQQDDBdhcGkuYnJpZ2h0bW9vci5p\n"
            "bnRlcm5hbDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGfm6TZHm6V8AfDjK3XO\n"
            "GVznagy08IiXlopOvJUyiq2w+9Wr30QXRkeeWukelmi+KGnC+6feidD8XCYX6AtC\n"
            "fnOjUzBRMB0GA1UdDgQWBBScehh+He9yhDHWU7YNN8BcA9MNBjAfBgNVHSMEGDAW\n"
            "gBScehh+He9yhDHWU7YNN8BcA9MNBjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49\n"
            "BAMCA0cAMEQCIFG/HSZz6/dMmMvF+Pdb0yr1vILw9y+523uTFpof+9FkAiBBMsyY\n"
            "8GoJw5jzmGUseneMfXZFnogk50+tSzZqpWbO4A==\n"
            "-----END CERTIFICATE-----"
        ),
        expected_secret=False,
        category="public_value",
    ),
    # secret: no - JWKS document: RSA public key components published for token verification.
    "sample_099": Case(
        file_path="web/public/.well-known/jwks.json",
        content=(
            "{\n"
            '  "keys": [\n'
            "    {\n"
            '      "kty": "RSA",\n'
            '      "use": "sig",\n'
            '      "alg": "RS256",\n'
            '      "kid": "a6429626353f28fd",\n'
            '      "n": "v2wWMDl5qYxXjbD7YG0h1it6PDi9beLJJ4SgQrgVdl1whs5ktxaKWFL5y7zpCPEl3c5lNLCblr3YlYzMMV_'
            "R70Q_018ta0j91DL-e1Loov2E2KA84d2SXFAAW4sX3Qe0pAcCLauqTqPwauO9Cw6KETvFI2OxcFdpO9TiaCDqZzBO4VpO1vaY5"
            "fzYaNNuOmWMx7P3DxHoel6pPdWmsgECqCKSUkncUzJvKtDmiW8ePJNs2XHkKScAEU2D6_9LAlGRVJwBxq5tcycCk5zlu-R6X36"
            'ZYvyB-JU1IBwfXfuKNWY6eSzE-JZTj3O3JQmNpyiFg-XCMlFNPqDljZHagIyBom",\n'
            '      "e": "AQAB"\n'
            "    }\n"
            "  ]\n"
            "}"
        ),
        expected_secret=False,
        category="public_value",
    ),
    # secret: no - Format-valid random token that the code explicitly marks as fake and uses against a mock.
    "sample_100": Case(
        file_path="tests/test_github_client.py",
        content=(
            'FAKE_TOKEN = "ghp_6WeM0TKfplE4pslKOG14l9kxjeoLvkEvphmz"  # not a real token, the GitHub API is m'
            "ocked below\n"
            "\n"
            "\n"
            "def test_lists_pull_requests(mock_github):\n"
            "    client = GitHubClient(token=FAKE_TOKEN)\n"
            "    assert client.pull_requests() == []"
        ),
        expected_secret=False,
        category="placeholder",
    ),
}
