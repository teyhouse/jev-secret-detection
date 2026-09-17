"""The Noul question(s) asked against each test case, and the model to ask."""

from typesafe_sdk import Noul

MODEL = "jev-latest"

QUESTIONS = {
    "contains_live_secret": Noul(
        instructions=(
            "Does this text contain a real, sensitive credential that could grant "
            "actual access to a system (an API key, password, token, or similar)?"
        ),
        criteria={
            "true": (
                "Contains what appears to be a live, working credential, a real key that could be used to authenticate"
            ),
            "false": (
                "Contains no credential, or only a placeholder/example/documentation "
                "credential that isn't functional and grants no access"
            ),
        },
    ),
}
