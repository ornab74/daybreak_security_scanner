from __future__ import annotations

import unittest
from datetime import datetime, timezone

from http_transport import RetryPolicy, is_retryable, retry_after_seconds, retry_call


class Response:
    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class StatusError(Exception):
    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.response = Response(status_code, headers)


class RetryTests(unittest.TestCase):
    def test_transient_statuses_only(self):
        self.assertTrue(is_retryable(StatusError(429)))
        self.assertTrue(is_retryable(StatusError(503)))
        self.assertFalse(is_retryable(StatusError(400)))
        self.assertFalse(is_retryable(StatusError(401)))

    def test_retry_after_variants(self):
        self.assertEqual(retry_after_seconds(StatusError(429, {"retry-after-ms": "1250"})), 1.25)
        self.assertEqual(retry_after_seconds(StatusError(429, {"retry-after": "3"})), 3.0)
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        error = StatusError(503, {"retry-after": "Thu, 01 Jan 2026 00:00:05 GMT"})
        self.assertEqual(retry_after_seconds(error, now), 5.0)

    def test_bounded_retry_then_success(self):
        calls = []
        delays = []

        def operation():
            calls.append(1)
            if len(calls) < 3:
                raise StatusError(503)
            return "ok"

        result = retry_call(
            operation,
            policy=RetryPolicy(max_attempts=5, base_delay=1, max_delay=10, max_total_delay=10),
            wait=lambda delay: delays.append(delay) or False,
            random_value=lambda: 0.0,
        )
        self.assertEqual(result, "ok")
        self.assertEqual(len(calls), 3)
        self.assertEqual(delays, [.5, 1.0])

    def test_authentication_failure_never_retried(self):
        calls = []
        with self.assertRaises(StatusError):
            retry_call(
                lambda: calls.append(1) or (_ for _ in ()).throw(StatusError(401)),
                policy=RetryPolicy(),
                wait=lambda _: False,
            )
        self.assertEqual(len(calls), 1)

    def test_cancellation_interrupts_backoff(self):
        with self.assertRaisesRegex(RuntimeError, "cancelled"):
            retry_call(
                lambda: (_ for _ in ()).throw(StatusError(503)),
                policy=RetryPolicy(),
                wait=lambda _: True,
            )


if __name__ == "__main__":
    unittest.main()
