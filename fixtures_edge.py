"""Edge batch: placeholders and redactions that resemble real values, paired with real secrets in the same shape."""

from fixtures import Case

CASES = {
    # secret: no - Slack's own documentation placeholder, correct xoxb- prefix but the body says it is fake.
    # Pair: edge_002.
    "edge_001": Case(
        file_path="scripts/notify_deploy.py",
        content=(
            "from slack_sdk import WebClient\n"
            "\n"
            'client = WebClient(token="xoxb-not-a-real-token-this-will-not-work")\n'
            'client.chat_postMessage(channel="#deploys", text=f"{service} {version} deployed")'
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Same script with a complete bot token. Pair: edge_001.
    "edge_002": Case(
        file_path="scripts/notify_deploy.py",
        content=(
            "from slack_sdk import WebClient\n"
            "\n"
            'client = WebClient(token="xoxb-9515900715-7062201202518-iilw0J7Y9974yOLJwmDLLJbA")\n'
            'client.chat_postMessage(channel="#deploys", text=f"{service} {version} deployed")'
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - Exact ghp_ length, but the body spells out a placeholder. Pair: edge_004.
    "edge_003": Case(
        file_path="README.md",
        content=(
            "## Authentication\n"
            "\n"
            "Create a personal access token with the `repo` scope and export it before running the sync:\n"
            "\n"
            "```bash\n"
            "export GITHUB_TOKEN=ghp_YourPersonalAccessTokenGoesHere12345\n"
            "repo-sync --org brightmoor\n"
            "```"
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Same README with a complete token pasted in. Pair: edge_003.
    "edge_004": Case(
        file_path="README.md",
        content=(
            "## Authentication\n"
            "\n"
            "Create a personal access token with the `repo` scope and export it before running the sync:\n"
            "\n"
            "```bash\n"
            "export GITHUB_TOKEN=ghp_3bhkyD9fvLbulK5G5fP5nK0sJtabFCfou7VM\n"
            "repo-sync --org brightmoor\n"
            "```"
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - Random-looking SendGrid key, but the comment marks it as a dummy for tests. Pair: edge_006.
    "edge_005": Case(
        file_path=".github/workflows/test.yml",
        content=(
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      # dummy value so the mailer boots in tests, the real key is only set in the deploy job\n"
            "      SENDGRID_API_KEY: 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\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: make test"
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Same workflow and key without the dummy comment. Pair: edge_005.
    "edge_006": Case(
        file_path=".github/workflows/test.yml",
        content=(
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    env:\n"
            "      SENDGRID_API_KEY: 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\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - run: make test"
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - Literal user:password in a deploy file, not an example path.
    "edge_007": Case(
        file_path="deploy/app.env",
        content="DATABASE_URL=postgres://user:password@localhost:5432/app\nREDIS_URL=redis://localhost:6379/0",
        expected_secret=False,
        category="placeholder",
    ),
    # secret: no - API spec example with a live-style prefix and sequential hex.
    "edge_008": Case(
        file_path="api/openapi.yaml",
        content=(
            "components:\n"
            "  securitySchemes:\n"
            "    ApiKeyAuth:\n"
            "      type: apiKey\n"
            "      in: header\n"
            "      name: X-API-Key\n"
            "      description: Your workspace API key, e.g. `bm_live_0123456789abcdef0123456789abcdef`"
        ),
        expected_secret=False,
        category="placeholder",
    ),
    # secret: yes - Example env file where a real live key was pasted next to non-secret defaults.
    "edge_009": Case(
        file_path=".env.example",
        content=(
            "# Copy to .env and fill in your own values\n"
            "REDIS_URL=redis://localhost:6379/0\n"
            "STRIPE_SECRET_KEY=sk_live_VYMsSgs8aTFGqmT6ozpqk2qW\n"
            "SENTRY_DSN="
        ),
        expected_secret=True,
        category="vendor_token",
    ),
    # secret: no - Production connection string in a log with the password masked. Pair: edge_011.
    "edge_010": Case(
        file_path="logs/migrate.log",
        content=(
            "2026-09-14T03:12:44Z INFO connecting to "
            "postgresql://billing_app:****@db-prod-02.brightmoor.internal:5432/billing?sslmode=require"
        ),
        expected_secret=False,
        category="redacted",
    ),
    # secret: yes - Same log line with the password written out. Pair: edge_010.
    "edge_011": Case(
        file_path="logs/migrate.log",
        content=(
            "2026-09-14T03:12:44Z INFO connecting to "
            "postgresql://billing_app:8rXImQJ7aClMb93cXIGx7ajV@db-prod-02.brightmoor.internal:5432/billing?sslmode=require"
        ),
        expected_secret=True,
        category="connection_string",
    ),
    # secret: yes - Redaction is present but incomplete: the password is masked, the Datadog API key is not.
    "edge_012": Case(
        file_path="logs/worker.log",
        content=(
            '2026-09-16T22:03:51Z ERROR sync failed config={"db_password": "***", '
            '"dd_api_key": "f58c5dda46c60f74dde82d105694a705", "region": "eu-west-1"}'
        ),
        expected_secret=True,
        category="embedded_credential",
    ),
    # secret: no - aws configure list output, which masks both keys down to the last four characters.
    "edge_013": Case(
        file_path="docs/troubleshooting/aws-cli.md",
        content=(
            "```\n"
            "$ aws configure list\n"
            "      Name                    Value             Type    Location\n"
            "      ----                    -----             ----    --------\n"
            "   profile                <not set>             None    None\n"
            "access_key     ****************KP7Y shared-credentials-file\n"
            "secret_key     ****************oO49 shared-credentials-file\n"
            "    region                eu-west-1      config-file    ~/.aws/config\n"
            "```"
        ),
        expected_secret=False,
        category="redacted",
    ),
    # secret: no - kubectl describe shows only the byte length of each secret value.
    "edge_014": Case(
        file_path="notes/incident-2026-09-02.md",
        content=(
            "$ kubectl describe secret billing-db -n billing\n"
            "Name:         billing-db\n"
            "Namespace:    billing\n"
            "Labels:       app=billing\n"
            "Annotations:  <none>\n"
            "\n"
            "Type:  Opaque\n"
            "\n"
            "Data\n"
            "====\n"
            "password:  32 bytes\n"
            "username:  11 bytes"
        ),
        expected_secret=False,
        category="redacted",
    ),
    # secret: no - Terraform plan hides the changed password as a sensitive value.
    "edge_015": Case(
        file_path="ci/artifacts/plan-output.txt",
        content=(
            "  # aws_db_instance.billing will be updated in-place\n"
            '  ~ resource "aws_db_instance" "billing" {\n'
            '        id                 = "billing-prod"\n'
            "      ~ password           = (sensitive value)\n"
            '        username           = "billing_app"\n'
            "        # (41 unchanged attributes hidden)\n"
            "    }"
        ),
        expected_secret=False,
        category="redacted",
    ),
    # secret: no - Bearer JWT cut off inside the payload, so there is no signature.
    "edge_016": Case(
        file_path="logs/payments-client.log",
        content=(
            "2026-09-15T11:20:03Z DEBUG POST https://payments.brightmoor.internal/v2/invoices "
            'auth="Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtYmlsbGluZyIsImF1ZCI6...'
            '" (truncated, 812 chars)'
        ),
        expected_secret=False,
        category="redacted",
    ),
    # secret: no - Private key block with only the first line (ASN.1 header and public modulus bytes) kept.
    "edge_017": Case(
        file_path="docs/incidents/2026-08-12-leaked-deploy-key.md",
        content=(
            "## What leaked\n"
            "\n"
            "The deploy key committed in `a3f9c21`, truncated here:\n"
            "\n"
            "```\n"
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDkDKtbo6OmuPu/\n"
            "... (25 more lines removed)\n"
            "-----END PRIVATE KEY-----\n"
            "```"
        ),
        expected_secret=False,
        category="redacted",
    ),
}
