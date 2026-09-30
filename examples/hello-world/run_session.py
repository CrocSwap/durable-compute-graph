#!/usr/bin/env python3
import asyncio, sys
from dcg.session import COUNTER_MANIFEST, KernelRef, Session

async def main():
    session = Session.from_environment(KernelRef.from_manifest(COUNTER_MANIFEST))
    opened = False
    try:
        await session.open()
        opened = True
        await session.write_input(int(sys.argv[1]))
        await session.advance(1)
        state = await session.read_state()
        print(f"input={sys.argv[1]} value={state.value} total={state.total}")
    finally:
        if opened:
            print(f"rent_refunded_lamports={(await session.close()).rent_lamports}")
        await session.aclose()

asyncio.run(main())
