from __future__ import annotations

import asyncio

from apscheduler.schedulers.blocking import BlockingScheduler

from .config import get_settings


def start_scheduler() -> None:
    from .cli import run_collection

    scheduler = BlockingScheduler()
    scheduler.add_job(
        lambda: asyncio.run(run_collection(None, False)),
        "interval",
        minutes=get_settings().schedule_minutes,
        id="metadata-collection",
        max_instances=1,
        coalesce=True,
    )
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown(wait=True)