"""The Noul question(s) asked against each test case, and the model to ask."""

from typesafe_sdk import Noul

# Pinned instead of jev-latest, so an alias move can't silently change the results.
MODEL = "jev-1.13.0"

QUESTIONS = {
    "contains_real_secret": Noul(
        instructions={
            "question": (
                "Does `content` contain a real secret credential that someone reading it could use to gain access?"
            ),
            "credential_types": [
                "API key or access token",
                "Password or passphrase",
                "Private key",
                "URL, header, or config entry that embeds one of these",
            ],
            "focus": "Judge the values actually written in `content`. Use `file_path` only as context.",
        },
        criteria={
            "true": {
                "what": "A complete credential value is written out and looks issued or chosen for real use",
                "includes": "Credentials that are only base64-encoded, which anyone can decode",
            },
            "false": {
                "what": "No usable credential value is written out",
                "does_not_count": [
                    "Placeholder, example, dummy, or test values",
                    "Redacted, masked, or truncated values",
                    "References to a secret stored elsewhere, such as an environment variable or secret manager",
                    "Encrypted values",
                    "Public keys and identifiers that are public by design",
                    "Hashes, checksums, commit SHAs, and IDs",
                    "Personal data that is not a login credential",
                ],
            },
        },
    ),
}
