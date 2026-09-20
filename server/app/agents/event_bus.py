"""
AegisAI Asynchronous Process-Local Event Bus
Provides non-blocking event publishing, typed subscriber dispatch, and error isolation.
"""
from __future__ import annotations

import asyncio
import inspect
from typing import Any, Callable, Dict, List, Type, TypeVar
from loguru import logger

from app.agents.schemas import BaseAgentEvent

E = TypeVar("E", bound=BaseAgentEvent)


class EventBus:
    """
    Lightweight asynchronous process-local Event Bus built on asyncio.Queue.
    Supports multiple concurrent typed subscribers, worker pools, and error isolation.
    """

    def __init__(self, max_queue_size: int = 1000, num_workers: int = 2):
        self._queue: asyncio.Queue[BaseAgentEvent] = asyncio.Queue(maxsize=max_queue_size)
        self._subscribers: Dict[Type[BaseAgentEvent], List[Callable[[Any], Any]]] = {}
        self._wildcard_subscribers: List[Callable[[BaseAgentEvent], Any]] = []
        self._workers: List[asyncio.Task] = []
        self._num_workers = num_workers
        self._running = False
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: Type[E], handler: Callable[[E], Any]) -> None:
        """Register a handler for a specific event type."""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        if handler not in self._subscribers[event_type]:
            self._subscribers[event_type].append(handler)
            logger.debug(f"[Event Bus] Subscribed {handler.__qualname__} to {event_type.__name__}")

    def subscribe_all(self, handler: Callable[[BaseAgentEvent], Any]) -> None:
        """Register a wildcard handler that receives all published events."""
        if handler not in self._wildcard_subscribers:
            self._wildcard_subscribers.append(handler)
            logger.debug(f"[Event Bus] Registered wildcard subscriber {handler.__qualname__}")

    def unsubscribe(self, event_type: Type[E], handler: Callable[[E], Any]) -> None:
        """Unregister a handler for an event type."""
        if event_type in self._subscribers and handler in self._subscribers[event_type]:
            self._subscribers[event_type].remove(handler)

    async def publish(self, event: BaseAgentEvent) -> None:
        """Publish an event onto the bus queue with burst buffering."""
        if not self._running:
            logger.warning(f"[Event Bus] Publish called while bus is stopped. Dropping {type(event).__name__}")
            return
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                await asyncio.wait_for(self._queue.put(event), timeout=2.0)
            except asyncio.TimeoutError:
                logger.error(f"[Event Bus] Queue full timeout! Dropping event {type(event).__name__}:{event.event_id}")

    async def start(self) -> None:
        """Start the background consumer worker pool."""
        async with self._lock:
            if self._running:
                return
            self._running = True
            self._workers = [
                asyncio.create_task(self._worker_loop(i), name=f"EventBus-Worker-{i}")
                for i in range(self._num_workers)
            ]
            logger.info(f"[Event Bus] Started with {self._num_workers} consumer workers.")

    async def stop(self) -> None:
        """Gracefully drain the queue and stop all workers."""
        async with self._lock:
            if not self._running:
                return
            self._running = False
            logger.info("[Event Bus] Stopping event bus workers...")

            # Allow brief window for pending queue items to drain
            if not self._queue.empty():
                try:
                    await asyncio.wait_for(self._queue.join(), timeout=1.5)
                except (asyncio.TimeoutError, Exception):
                    pass

            # Cancel running workers
            for worker in self._workers:
                worker.cancel()

            await asyncio.gather(*self._workers, return_exceptions=True)
            self._workers.clear()
            logger.info("[Event Bus] Stopped successfully.")

    async def _worker_loop(self, worker_id: int) -> None:
        """Worker loop reading events from queue and dispatching to subscribers."""
        while self._running:
            try:
                event = await self._queue.get()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[Event Bus] Worker {worker_id} error fetching from queue: {e}")
                continue

            try:
                await self._dispatch(event)
            except Exception as e:
                logger.error(f"[Event Bus] Unhandled exception dispatching {type(event).__name__}: {e}")
            finally:
                self._queue.task_done()

    async def _dispatch(self, event: BaseAgentEvent) -> None:
        """Dispatch event to typed subscribers and wildcard subscribers."""
        event_cls = type(event)
        handlers: List[Callable] = []

        # Find matching handlers (exact match or subclass)
        for sub_cls, sub_handlers in self._subscribers.items():
            if issubclass(event_cls, sub_cls):
                handlers.extend(sub_handlers)

        # Include wildcard handlers
        handlers.extend(self._wildcard_subscribers)

        for handler in handlers:
            try:
                if inspect.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as ex:
                logger.error(
                    f"[Event Bus] Handler '{handler.__qualname__}' failed on {event_cls.__name__} "
                    f"(ID: {getattr(event, 'event_id', 'unknown')}): {ex}"
                )
