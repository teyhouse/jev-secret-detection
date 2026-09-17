"""Sample states for the secret-detection Noul test.

Named neutrally (sample_a, sample_b, ...) so the case name doesn't give away the
expected verdict. Each entry's ground truth (`expected_secret`) and provenance are
documented in the comment directly above it.
"""

from typing import NamedTuple


class Case(NamedTuple):
    state: str
    expected_secret: bool


CASES = {
    # -- generic cases -----------------------------------------------------
    # secret: yes - live-looking Stripe secret key inside a leaked .env-style snippet
    "sample_a": Case(
        state=(
            "STRIPE_SECRET_KEY=sk_live_51NxjshD82ktPfQmR7scv1YbHo4WgTz93U6qLpBaFnEcXyRj80\n"
            "DATABASE_URL=postgres://svc_billing:Tr0ub4dor%263@prod-db.internal:5432/billing"
        ),
        expected_secret=True,
    ),
    # secret: no - ordinary application code, no credentials involved
    "sample_b": Case(
        state=(
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n\n"
            "# TODO: add unit tests for this function before the next release"
        ),
        expected_secret=False,
    ),
    # secret: no - AWS's own documentation placeholder key pair (widely allowlisted by
    # scanners like gitleaks); correct format and entropy, never a functional credential
    "sample_c": Case(
        state=(
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ),
        expected_secret=False,
    ),
    # -- source: github.com/gitleaks/gitleaks -------------------------------
    # secret: yes (literal Sidekiq Enterprise secret example from gitleaks' own
    # sidekiq-secret rule docs) - source: https://github.com/gitleaks/gitleaks
    "sample_d": Case(
        state="export BUNDLE_ENTERPRISE__CONTRIBSYS__COM=cafebabe:deadbeef",
        expected_secret=True,
    ),
    # secret: no (literal SSN test value from gitleaks' own PII allowlist docs,
    # intentionally non-real) - source: https://github.com/gitleaks/gitleaks
    "sample_e": Case(
        state="customer_ssn=219-09-9999",
        expected_secret=False,
    ),
    # secret: no (literal SSN test value from gitleaks' own PII allowlist docs;
    # this specific number is the famous 1938 "Woolworth wallet" specimen SSN
    # that ended up misused for decades) - source: https://github.com/gitleaks/gitleaks
    "sample_f": Case(
        state="ssn_on_file=078-05-1120",
        expected_secret=False,
    ),
    # secret: yes (constructed in the ghp_ format of the github-pat detector that
    # gitleaks ships) - source: https://github.com/gitleaks/gitleaks
    "sample_g": Case(
        state="GITHUB_TOKEN=ghp_9fK3mQ7pL2xZ8vN4bR6tC1wY5eU0oAsDfGh3",
        expected_secret=True,
    ),
    # secret: yes (constructed in the xoxb- format of the slack-bot-token detector
    # that gitleaks ships) - source: https://github.com/gitleaks/gitleaks
    "sample_h": Case(
        state="SLACK_BOT_TOKEN=xoxb-778520834561-8934771029443-XjK9pQmR3vLtNzS7cWkYbA2f",
        expected_secret=True,
    ),
    # -- source: decryptiondigest.com (secrets-scanning-pre-commit-ci-enforcement) --
    # secret: no (uses the literal "EXAMPLE_API_KEY" placeholder token the article
    # cites as an allowlisted documentation value)
    # source: https://www.decryptiondigest.com/blog/secrets-scanning-pre-commit-ci-enforcement
    "sample_i": Case(
        state="API_KEY=EXAMPLE_API_KEY_REPLACE_ME",
        expected_secret=False,
    ),
    # secret: no (matches the literal "test_token_.*" allowlist regex the article cites)
    # source: https://www.decryptiondigest.com/blog/secrets-scanning-pre-commit-ci-enforcement
    "sample_j": Case(
        state="AUTH_TOKEN=test_token_9f8a3c2e1b7d4d21",
        expected_secret=False,
    ),
    # secret: yes (constructed in the GCP API key format, one of the "150+ secret
    # types including AWS, GCP, GitHub, Stripe, Twilio" the article lists)
    # source: https://www.decryptiondigest.com/blog/secrets-scanning-pre-commit-ci-enforcement
    "sample_k": Case(
        state="GOOGLE_API_KEY=AIzaSyD4kL9pQmX2vN7bRt5cWjH8sFo3EuY6IdA",
        expected_secret=True,
    ),
    # secret: yes (constructed in the Twilio auth-token format, another type from
    # the article's supported-detectors list)
    # source: https://www.decryptiondigest.com/blog/secrets-scanning-pre-commit-ci-enforcement
    "sample_l": Case(
        state="TWILIO_AUTH_TOKEN=8f3ac91b2e47d6c0a9f8b3e7d2c1a4f6",
        expected_secret=True,
    ),
    # secret: no (a gitleaks allowlist config snippet as described by the article;
    # it references placeholder patterns but carries no credential itself)
    # source: https://www.decryptiondigest.com/blog/secrets-scanning-pre-commit-ci-enforcement
    "sample_m": Case(
        state='[[allowlist]]\nregexes = ["EXAMPLE_API_KEY", "test_token_.*"]',
        expected_secret=False,
    ),
    # -- source: docs.gitguardian.com (generic_high_entropy_secret detector) -------
    # secret: yes (literal doc example: high-entropy value assigned to "auth", caught)
    # source: https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/generics/generic_high_entropy_secret
    "sample_n": Case(
        state='auth = "bsaruceobkoraebisroaecbu89"',
        expected_secret=True,
    ),
    # secret: yes (literal doc example: high-entropy value detected in a "token" assignment)
    # source: https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/generics/generic_high_entropy_secret
    "sample_o": Case(
        state='token = "buaroeuboesanubo234reacubrch"',
        expected_secret=True,
    ),
    # secret: yes (literal doc example: high-entropy string containing an escaped
    # backslash character, assigned to a sensitive key name)
    # source: https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/generics/generic_high_entropy_secret
    "sample_p": Case(
        state='secret_key = "d1Hb1f\\b497XGT75989e"',
        expected_secret=True,
    ),
    # secret: no (literal doc example: the exact same high-entropy string as above,
    # but flagged as a false positive because the variable name "object_id" lacks
    # a sensitive keyword) - source: https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/generics/generic_high_entropy_secret
    "sample_q": Case(
        state='object_id = "hj65_klhz/trlupok76"',
        expected_secret=False,
    ),
    # secret: no (literal doc example: sensitive keyword present, but the repetitive
    # string has insufficient entropy)
    # source: https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/generics/generic_high_entropy_secret
    "sample_r": Case(
        state='session_token = "xob1xob1xob1xob1xob1xob1xob1"',
        expected_secret=False,
    ),
    # -- source: cremit.io (secret-scanning-false-positives-causes-and-fixes) ------
    # secret: no (the literal AWS documentation placeholder key the article calls out
    # as "copied straight out of the AWS docs", shown here in a Terraform block)
    # source: https://www.cremit.io/blog/secret-scanning-false-positives-causes-and-fixes
    "sample_s": Case(
        state=(
            'provider "aws" {\n'
            '  access_key = "AKIAIOSFODNN7EXAMPLE"\n'
            '  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
            "}"
        ),
        expected_secret=False,
    ),
    # secret: no (a git commit SHA, one of the high-entropy-but-benign categories the
    # article lists; this one is git's well-known empty-tree hash)
    # source: https://www.cremit.io/blog/secret-scanning-false-positives-causes-and-fixes
    "sample_t": Case(
        state="parent_commit=4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        expected_secret=False,
    ),
    # secret: no (a UUID, one of the high-entropy-but-benign categories the article lists)
    # source: https://www.cremit.io/blog/secret-scanning-false-positives-causes-and-fixes
    "sample_u": Case(
        state="request_id=550e8400-e29b-41d4-a716-446655440000",
        expected_secret=False,
    ),
    # secret: no (a base64-encoded image fragment, one of the categories the article
    # lists as a common false positive)
    # source: https://www.cremit.io/blog/secret-scanning-false-positives-causes-and-fixes
    "sample_v": Case(
        state=(
            "thumbnail=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"
            "CAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
        ),
        expected_secret=False,
    ),
    # secret: no (a dependency lockfile integrity hash, one of the categories the
    # article lists as a common false positive)
    # source: https://www.cremit.io/blog/secret-scanning-false-positives-causes-and-fixes
    "sample_w": Case(
        state=(
            '"integrity": "sha512-1qWnhF/BAAWVzXWVWMKb9Zto/eKwGyGkAJKA0v5oXKG4xZKxJp/nq1PISvK'
            'zHKQMHbAADkeVUQBBv+LuBAT7XA=="'
        ),
        expected_secret=False,
    ),
}
