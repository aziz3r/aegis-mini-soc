"""In-process publish/subscribe for the live WebSocket stream.

Deliberately not Redis. A single-process deployment does not need a broker, and
introducing one would add an operational dependency for no behavioural gain. The
interface is narrow on purpose - `publish` / `subscribe` - so a Redis Streams or
Kafka adapter can replace it without touching the pipeline or the API.

The one property that matters: a slow subscriber must never slow the pipeline.
Each subscriber owns a bounded queue and loses its oldest events when it cannot
keep up. Dropping frames for one browser tab is always better than stalling
packet ingestion for everyone.
"""
from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterator
from typing import Any

QUEUE_LIMIT = 256


class Subscription:
    def __init__(self, bus: "Bus") -> None:
        self._bus = bus
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=QUEUE_LIMIT)
        self.dropped = 0

    def offer(self, event: dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                self._queue.get_nowait()   # discard the oldest, keep the newest
                self._queue.put_nowait(event)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass
            self.dropped += 1

    async def __aiter__(self) -> AsyncIterator[dict[str, Any]]:
        try:
            while True:
                yield await self._queue.get()
        finally:
            self._bus.unsubscribe(self)

    def close(self) -> None:
        self._bus.unsubscribe(self)


class Bus:
    def __init__(self, history: int = 180) -> None:
        self._subscribers: set[Subscription] = set()
        self._history: deque[dict[str, Any]] = deque(maxlen=history)
        self.published = 0

    def subscribe(self) -> Subscription:
        sub = Subscription(self)
        self._subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        self._subscribers.discard(sub)

    def publish(self, event: dict[str, Any]) -> None:
        self.published += 1
        if event.get("type") == "tick":
            self._history.append(event)
        for sub in list(self._subscribers):
            sub.offer(event)

    def history(self) -> list[dict[str, Any]]:
        """Recent ticks, so a page that just opened has a populated chart."""
        return list(self._history)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)
