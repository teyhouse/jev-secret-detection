"""Async Noul test: does a file snippet contain a real secret credential?"""

import asyncio
import sys
import time

from dotenv import load_dotenv
from typesafe_sdk import AsyncTypeSafeClient

from fixtures import CASES, Case
from fixtures_config import CASES as CONFIG_CASES
from fixtures_edge import CASES as EDGE_CASES
from questions import MODEL, QUESTIONS
from utils import Result, print_report

load_dotenv()

# Firing every case at once queues requests behind each other's TLS handshakes and 529 retries, which inflated the
# measured round trip from ~300 ms to ~2 s. A bounded pool keeps each timing close to a lone request.
CONCURRENCY = 16

BATCHES = {"main": CASES, "edge": EDGE_CASES, "config": CONFIG_CASES}


async def run_case(client: AsyncTypeSafeClient, pool: asyncio.Semaphore, name: str, case: Case) -> Result:
    state = {"file_path": case.file_path, "content": case.content}
    async with pool:
        start = time.perf_counter()
        result = await client.system_one(state=state, questions=QUESTIONS, model=MODEL)
        elapsed_ms = (time.perf_counter() - start) * 1000
    response = result.raw_http_response
    # Undocumented envoy header: time spent behind the API gateway, so it leaves out the network round trip.
    server_ms = response.headers.get("x-envoy-upstream-service-time")
    retries = int(response.request.headers.get("X-TypeSafe-Retry-Count", 0))
    noul = result.nouls["contains_real_secret"].noul
    return Result(
        name,
        case.category,
        case.expected_secret,
        noul,
        elapsed_ms,
        float(server_ms) if server_ms else None,
        retries,
    )


async def main(cases: dict[str, Case]) -> None:
    pool = asyncio.Semaphore(CONCURRENCY)
    async with AsyncTypeSafeClient() as client:
        # Open the pool's connections with model listings first, so TLS setup does not land in the timings.
        await asyncio.gather(*(client.models.list() for _ in range(CONCURRENCY)))
        start = time.perf_counter()
        results = await asyncio.gather(*(run_case(client, pool, name, case) for name, case in cases.items()))
        wall_s = time.perf_counter() - start

    print_report(list(results), wall_s, CONCURRENCY)


if __name__ == "__main__":
    batch = sys.argv[1] if sys.argv[1:] else "main"
    if batch not in BATCHES:
        sys.exit(f"unknown batch {batch!r}, pick one of: {', '.join(BATCHES)}")
    asyncio.run(main(BATCHES[batch]))
