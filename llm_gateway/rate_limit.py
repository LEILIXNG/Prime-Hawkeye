"""Surviving the provider saying "429, slow down".

This project's endpoint is a free tier (see MEMORY.md): a 429 is not an
exceptional condition here, it is the normal cost of running a scan with
several verify calls in flight. Before this, one of them ended the scan --
`failed`, no report, and the Semgrep work that had already succeeded thrown
away. A minute of waiting is worth more than that.

The retry lives at the provider boundary rather than in scanner/verify.py so
that recognising a rate limit stays the one place that knows which SDK is
underneath, and everything above it can stay provider-agnostic.
"""
import sys
import time

MAX_ATTEMPTS = 4

# 2s, 4s, 8s between the four attempts -- 14 seconds of waiting before a call
# is given up on. Long enough to clear the per-minute window most free tiers
# reset on, short enough that a genuinely exhausted quota does not hold a
# scan for minutes per candidate before the partial report gets written.
BASE_DELAY_SECONDS = 2.0
MAX_DELAY_SECONDS = 30.0


class ProviderExhausted(Exception):
    """Every attempt at one call failed in a way retrying was meant to cure.

    Distinct from the provider's own error so callers above the gateway can
    tell "the endpoint is not answering us right now" from "the request was
    malformed", and treat only the first as something a scan can carry on
    past (scanner/pipeline.py keeps what was already verified).
    """

    def __init__(self, message: str, attempts: int, last_error: BaseException):
        super().__init__(message)
        self.attempts = attempts
        self.last_error = last_error


class RateLimitExhausted(ProviderExhausted):
    """Every attempt came back rate-limited (429)."""

    def __init__(self, attempts: int, last_error: BaseException):
        super().__init__(f"rate limited by the provider after {attempts} attempts: {last_error}",
                         attempts, last_error)


class ProviderUnavailable(ProviderExhausted):
    """Every attempt failed to connect, timed out, or got a 5xx."""

    def __init__(self, attempts: int, last_error: BaseException):
        super().__init__(f"provider unreachable after {attempts} attempts: {last_error}",
                         attempts, last_error)


# A dropped connection or a gateway 5xx is as transient as a 429, and it was
# ending whole scans the same way: measured on HA_Benchmark (384 candidates),
# two full runs in a row failed outright at 65/384 and 129/384 on a single
# "Connection error." while the endpoint answered fine seconds later. The
# openai SDK's own two quick retries do not outlast that.
TRANSIENT_ERROR_NAMES = frozenset({
    "APIConnectionError", "APITimeoutError", "InternalServerError",
    "ConnectError", "ConnectTimeout", "ReadTimeout", "ReadError", "RemoteProtocolError",
})
TRANSIENT_STATUS_CODES = frozenset({500, 502, 503, 504, 529})


def is_transient(error: BaseException) -> bool:
    if type(error).__name__ in TRANSIENT_ERROR_NAMES:
        return True
    status = getattr(error, "status_code", None)
    if status is None:
        status = getattr(getattr(error, "response", None), "status_code", None)
    return status in TRANSIENT_STATUS_CODES


def is_rate_limited(error: BaseException) -> bool:
    """Whether an exception from a provider SDK is a 429.

    Deliberately generous. Reading it wrong in one direction costs a few
    seconds of pointless retrying; in the other it costs the scan, which is
    the failure this module exists to remove. openai raises RateLimitError
    with .status_code, self-hosted gateways in front of the same protocol
    tend to surface an httpx response instead, and some wrappers only put
    the code in the message.
    """
    status = getattr(error, "status_code", None)
    if status is None:
        status = getattr(getattr(error, "response", None), "status_code", None)
    if status == 429:
        return True
    if type(error).__name__ in ("RateLimitError", "TooManyRequests"):
        return True
    return "429" in str(error)


def retry_after_seconds(error: BaseException) -> float | None:
    """The provider's own Retry-After, when it sent one. Its number beats
    our guess: it knows when the window resets and we are estimating."""
    headers = getattr(getattr(error, "response", None), "headers", None)
    if headers is None:
        return None
    try:
        value = headers.get("retry-after")
    except AttributeError:
        return None
    try:
        return max(0.0, min(float(value), MAX_DELAY_SECONDS))
    except (TypeError, ValueError):
        return None


def delay_before(attempt: int, error: BaseException) -> float:
    """Seconds to wait before attempt number `attempt` (1-based, so the
    first retry is attempt 2)."""
    told = retry_after_seconds(error)
    if told is not None:
        return told
    return min(BASE_DELAY_SECONDS * 2 ** (attempt - 2), MAX_DELAY_SECONDS)


def call_with_retry(send, attempts: int = MAX_ATTEMPTS, sleep=None):
    """Call `send()`, retrying with backoff while the provider answers 429,
    or fails transiently (is_transient: connection error, timeout, 5xx).

    Anything else is re-raised untouched on the first try -- a malformed
    request does not get better by being sent again.
    `sleep` is injected so tests can assert the backoff without spending it;
    resolved here rather than as a default argument, which would bind
    time.sleep at import and quietly ignore a patched one.
    """
    sleep = sleep or time.sleep
    for attempt in range(1, attempts + 1):
        try:
            return send()
        except Exception as e:
            limited = is_rate_limited(e)
            if not limited and not is_transient(e):
                raise
            if attempt == attempts:
                raise (RateLimitExhausted if limited else ProviderUnavailable)(attempts, e) from e
            wait = delay_before(attempt + 1, e)
            print(f"[llm] {'rate limited' if limited else f'transient error ({type(e).__name__})'}, "
                  f"retrying in {wait:.0f}s (attempt {attempt + 1}/{attempts})", file=sys.stderr)
            sleep(wait)
