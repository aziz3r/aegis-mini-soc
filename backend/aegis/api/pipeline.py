"""The live pipeline: one asyncio task that owns the whole detection path.

    source -> engine (flows, scores, thresholds) -> correlator -> writer -> bus

Design notes worth knowing before changing anything here:

* **One writer.** The engine, the correlator and the database writer all live in
  this single task. That removes every lock and every race, and with SQLite in WAL
  mode the API can keep reading while this task writes.
* **Database work is offloaded.** Flushes run in a thread executor. They are
  blocking calls, and leaving them on the event loop would freeze the API for the
  duration of every commit.
* **Ticks are wall-clock.** Charts and incident timestamps use arrival time;
  capture time is preserved separately on each alert (`flow_start` / `flow_end`),
  so a PCAP replayed at x60 still produces correct flows while the UI shows a
  compressed, watchable timeline.
"""
from __future__ import annotations

import asyncio
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from aegis.api.bus import Bus
from aegis.config import settings
from aegis.core.assets import AssetRegistry
from aegis.core.correlate import Correlator, IncidentEvent
from aegis.core.engine import Engine
from aegis.core.types import Verdict
from aegis.ml.model import DetectionModel
from aegis.ml.threshold import AdaptiveThreshold
from aegis.sources.stream import LabSource, LiveSource, PcapSource, Source
from aegis.store.writer import BucketDelta, HostDelta, Writer

HOUSEKEEPING_EVERY = 2.0


class Pipeline:
    """Owns the detection task. Start one source at a time."""

    def __init__(self, model: DetectionModel, assets: AssetRegistry | None = None,
                 bus: Bus | None = None) -> None:
        self.model = model
        self.assets = assets or AssetRegistry()
        self.bus = bus or Bus(history=settings.stream_history)
        self.writer = Writer()
        self.engine = Engine(model, assets=self.assets, thresholds=AdaptiveThreshold())
        self.correlator = Correlator(self.assets)
        self.source: Source | None = None
        self._task: asyncio.Task | None = None
        self._stopping = False
        self.started_at: datetime | None = None
        self.error: str | None = None
        self._last_pkt_ts = 0.0
        self._last_housekeeping = 0.0

    # -- lifecycle ------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start_lab(self, duration: float = 3600.0, speed: float = 1.0,
                        seed: int | None = None, density: float = 1.0,
                        stealth_ratio: float = 0.25) -> None:
        await self._start(LabSource(duration=duration, speed=speed, seed=seed,
                                    density=density, stealth_ratio=stealth_ratio))

    async def start_pcap(self, path: Path, speed: float = 10.0) -> None:
        await self._start(PcapSource(path, speed=speed))

    async def start_live(self, iface: str, bpf: str = "ip") -> None:
        await self._start(LiveSource(iface, bpf=bpf))

    async def _start(self, source: Source) -> None:
        if self.is_running:
            await self.stop()
        # A fresh engine per run: flow state and host baselines from a previous
        # source must not leak into the next one.
        self.engine = Engine(self.model, assets=self.assets, thresholds=AdaptiveThreshold())
        self.correlator = Correlator(self.assets)
        self.source = source
        self.error = None
        self._stopping = False
        self.started_at = datetime.now(timezone.utc)
        self._task = asyncio.create_task(self._run(source), name=f"aegis-pipeline-{source.kind}")
        self.bus.publish({"type": "pipeline", "state": "started", "source": source.describe()})

    async def stop(self) -> None:
        self._stopping = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        if self.source is not None:
            await self.source.close()
        self.bus.publish({"type": "pipeline", "state": "stopped"})

    # -- the loop -------------------------------------------------------------

    async def _run(self, source: Source) -> None:
        loop = asyncio.get_running_loop()
        bucket = BucketDelta(ts=datetime.now(timezone.utc))
        hosts: dict[str, HostDelta] = {}
        events: list[IncidentEvent] = []
        next_tick = time.time() + settings.stream_tick
        try:
            async for batch in source.batches():
                if batch:
                    self._last_pkt_ts = batch[-1].ts
                    verdicts = self.engine.feed_packets(batch)
                    self._absorb(verdicts, bucket, hosts, events)

                now = time.time()
                if now - self._last_housekeeping >= HOUSEKEEPING_EVERY:
                    self._last_housekeeping = now
                    clock = now if source.kind == "live" else self._last_pkt_ts
                    self._absorb(self.engine.housekeeping(clock), bucket, hosts, events)

                if now >= next_tick:
                    next_tick = now + settings.stream_tick
                    await self._tick(loop, bucket, hosts, events, source)
                    bucket = BucketDelta(ts=datetime.now(timezone.utc))
                    hosts, events = {}, []

            # end of capture: flush whatever is still open
            self._absorb(self.engine.finish(), bucket, hosts, events)
            await self._tick(loop, bucket, hosts, events, source)
            self.bus.publish({"type": "pipeline", "state": "finished", "source": source.describe()})
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - surfaced to the UI instead
            self.error = f"{type(exc).__name__}: {exc}"
            self.bus.publish({"type": "pipeline", "state": "error", "error": self.error,
                              "traceback": traceback.format_exc()[-2000:]})

    def _absorb(self, verdicts: list[Verdict], bucket: BucketDelta,
                hosts: dict[str, HostDelta], events: list[IncidentEvent]) -> None:
        now = datetime.now(timezone.utc)
        for v in verdicts:
            flow = v.flow
            bucket.flows += 1
            bucket.packets += flow.packets
            bucket.bytes += flow.bytes
            bucket.score_sum += v.score
            bucket.score_max = max(bucket.score_max, v.score)
            bucket.threshold_sum += v.threshold

            src = hosts.setdefault(flow.key.src, HostDelta())
            src.flows_out += 1
            src.bytes_out += flow.fwd_bytes
            src.score_sum += v.score
            src.score_n += 1
            src.threshold = v.threshold
            src.calibrated = self.engine.thresholds.is_host_calibrated(flow.key.src)
            src.last_seen = now

            dst = hosts.setdefault(flow.key.dst, HostDelta())
            dst.flows_in += 1
            dst.bytes_in += flow.bwd_bytes
            dst.last_seen = now

            if v.is_alert:
                bucket.alerts += 1
                src.alerts += 1
                events.append(self.correlator.ingest(v, now))

    async def _tick(self, loop, bucket: BucketDelta, hosts: dict[str, HostDelta],
                    events: list[IncidentEvent], source: Source) -> None:
        payloads = []
        if events:
            payloads = await loop.run_in_executor(None, self.writer.flush_incidents, events)
        if bucket.flows or bucket.alerts:
            await loop.run_in_executor(None, self.writer.flush_bucket, bucket)
        if hosts:
            await loop.run_in_executor(None, self.writer.flush_hosts, hosts, self.assets)
        self.correlator.sweep()

        self.bus.publish({
            "type": "tick",
            **bucket.as_point(),
            "incidents": payloads,
            "stats": self.engine.stats.as_dict(),
            "source": source.describe(),
            "active_flows": self.engine.table.active_flows,
            "open_incidents": len(self.correlator.active),
        })

    # -- introspection --------------------------------------------------------

    def status(self) -> dict:
        return {
            "running": self.is_running,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "error": self.error,
            "source": self.source.describe() if self.source else None,
            "stats": self.engine.stats.as_dict(),
            "active_flows": self.engine.table.active_flows,
            "open_incidents": len(self.correlator.active),
            "incidents_opened": self.correlator.incidents_opened,
            "alerts_merged": self.correlator.alerts_merged,
            "written": {
                "incidents": self.writer.incidents_written,
                "alerts": self.writer.alerts_written,
                "alerts_dropped": self.writer.alerts_dropped,
            },
            "subscribers": self.bus.subscriber_count,
            "model": {
                "trained_at": self.model.meta.trained_at,
                "classes": self.model.meta.classes or [],
            },
        }
