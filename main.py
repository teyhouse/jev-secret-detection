"""Async Noul test: does a file snippet contain a real secret credential?"""

import asyncio
import time

from dotenv import load_dotenv
from typesafe_sdk import AsyncTypeSafeClient

from fixtures import CASES, Case
from questions import MODEL, QUESTIONS
from utils import Result, print_report

load_dotenv()


async def run_case(client: AsyncTypeSafeClient, name: str, case: Case) -> Result:
    state = {"file_path": case.file_path, "content": case.content}
    start = time.perf_counter()
    result = await client.system_one(state=state, questions=QUESTIONS, model=MODEL)
    elapsed_ms = (time.perf_counter() - start) * 1000
    noul = result.nouls["contains_real_secret"].noul
    return Result(name, case.category, case.expected_secret, noul, elapsed_ms)


async def main() -> None:
    async with AsyncTypeSafeClient() as client:
        results = await asyncio.gather(*(run_case(client, name, case) for name, case in CASES.items()))

    print_report(list(results))


if __name__ == "__main__":
    asyncio.run(main())
