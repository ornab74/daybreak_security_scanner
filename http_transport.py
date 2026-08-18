"""Bounded HTTPX transport and retry policy for remote model calls."""
from __future__ import annotations

import email.utils
import os
import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, TypeVar

T = TypeVar("T")
RETRYABLE_STATUS = frozenset({408, 409, 425, 429})


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    base_delay: float = 0.6
    max_delay: float = 15.0
    max_total_delay: float = 45.0

    @classmethod
    def from_environment(cls) -> "RetryPolicy":
        def number(name: str, default: float, low: float, high: float) -> float:
            try:
                value = float(os.getenv(name, str(default)))
            except ValueError:
                value = default
            return min(high, max(low, value))

        return cls(
            max_attempts=int(number("DAYBREAK_HTTP_ATTEMPTS", 5, 1, 10)),
            base_delay=number("DAYBREAK_HTTP_BASE_DELAY", .6, .05, 10),
            max_delay=number("DAYBREAK_HTTP_MAX_DELAY", 15, .1, 120),
            max_total_delay=number("DAYBREAK_HTTP_DELAY_BUDGET", 45, 0, 300),
        )


def build_httpx_client():
    """Create the only HTTP connection pool used by the OpenAI SDK."""
    import httpx

    timeout = httpx.Timeout(
        timeout=None,
        connect=float(os.getenv("DAYBREAK_HTTP_CONNECT_TIMEOUT", "5")),
        read=float(os.getenv("DAYBREAK_HTTP_READ_TIMEOUT", "90")),
        write=float(os.getenv("DAYBREAK_HTTP_WRITE_TIMEOUT", "30")),
        pool=float(os.getenv("DAYBREAK_HTTP_POOL_TIMEOUT", "5")),
    )
    limits = httpx.Limits(
        max_connections=20,
        max_keepalive_connections=10,
        keepalive_expiry=30.0,
    )
    return httpx.Client(
        timeout=timeout,
        limits=limits,
        follow_redirects=False,
        transport=httpx.HTTPTransport(retries=0),
        headers={"User-Agent": "Daybreak-Security-Workbench/4.1"},
        trust_env=True,
    )


def _status_code(exc: BaseException) -> int | None:
    status = getattr(exc, "status_code", None)
    response = getattr(exc, "response", None)
    if status is None and response is not None:
        status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def _header(exc: BaseException, name: str) -> str | None:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        value = headers.get(name)
    except Exception:
        return None
    return str(value).strip() if value is not None else None


def retry_after_seconds(exc: BaseException, now: datetime | None = None) -> float | None:
    milliseconds = _header(exc, "retry-after-ms")
    if milliseconds:
        try:
            return max(0.0, float(milliseconds) / 1000.0)
        except ValueError:
            pass
    value = _header(exc, "retry-after")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, (parsed - (now or datetime.now(timezone.utc))).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def is_retryable(exc: BaseException) -> bool:
    status = _status_code(exc)
    if status is not None:
        return status in RETRYABLE_STATUS or 500 <= status <= 599
    # SDK network/timeout exceptions preserve an httpx cause. Name checks keep
    # this module importable for deterministic tests without optional packages.
    names = {type(exc).__name__}
    cause = exc.__cause__
    while cause is not None:
        names.add(type(cause).__name__)
        cause = cause.__cause__
    return bool(names & {
        "APIConnectionError", "APITimeoutError", "ConnectError", "ConnectTimeout",
        "ReadError", "ReadTimeout", "WriteError", "WriteTimeout", "PoolTimeout",
        "RemoteProtocolError", "NetworkError",
    })


def retry_call(
    operation: Callable[[], T],
    *,
    policy: RetryPolicy,
    cancelled: Callable[[], bool] = lambda: False,
    wait: Callable[[float], bool] | None = None,
    on_retry: Callable[[int, float, BaseException], None] | None = None,
    random_value: Callable[[], float] = random.random,
) -> T:
    """Retry a synchronous operation with full jitter and a total sleep budget.

    ``wait`` returns True when cancellation interrupted the wait. Authentication,
    permission, validation, and other non-transient HTTP failures are never retried.
    """
    slept = 0.0
    last_error: BaseException | None = None
    for attempt in range(1, policy.max_attempts + 1):
        if cancelled():
            raise RuntimeError("Request cancelled before transmission.") from last_error
        try:
            return operation()
        except Exception as exc:
            last_error = exc
            if attempt >= policy.max_attempts or not is_retryable(exc):
                raise
            server_delay = retry_after_seconds(exc)
            if server_delay is None:
                ceiling = min(policy.max_delay, policy.base_delay * (2 ** (attempt - 1)))
                delay = ceiling * (.5 + .5 * random_value())
            else:
                delay = min(policy.max_delay, server_delay)
            remaining = policy.max_total_delay - slept
            if remaining <= 0:
                raise
            delay = min(delay, remaining)
            if on_retry:
                on_retry(attempt, delay, exc)
            interrupted = wait(delay) if wait else _sleep(delay, cancelled)
            if interrupted or cancelled():
                raise RuntimeError("Request cancelled during retry backoff.") from exc
            slept += delay
    raise RuntimeError("Retry loop exhausted.") from last_error


def _sleep(seconds: float, cancelled: Callable[[], bool]) -> bool:
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        if cancelled():
            return True
        time.sleep(min(.1, remaining))
