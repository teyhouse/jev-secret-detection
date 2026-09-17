"""Async Noul test: does a text state contain a live, working secret?"""

import asyncio
import time

from dotenv import load_dotenv
from typesafe_sdk import AsyncTypeSafeClient

from fixtures import CASES, Case
from questions import MODEL, QUESTIONS
from utils import print_table

load_dotenv()


async def run_case(client: AsyncTypeSafeClient, name: str, case: Case) -> tuple[str, float, str, float, bool]:
    start = time.perf_counter()
    result = await client.system_one(state=case.state, questions=QUESTIONS, model=MODEL)
    elapsed_ms = (time.perf_counter() - start) * 1000
    answer = result.nouls["contains_live_secret"]
    predicted_secret = answer.noul >= 0.5
    verdict = "LIVE SECRET" if predicted_secret else "no live secret"
    correct = predicted_secret == case.expected_secret
    return name, answer.noul, verdict, elapsed_ms, correct


async def main() -> None:
    async with AsyncTypeSafeClient() as client:
        results = await asyncio.gather(*(run_case(client, name, case) for name, case in CASES.items()))

    print_table(list(results))


if __name__ == "__main__":
    asyncio.run(main())
