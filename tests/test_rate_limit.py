"""The 429 retry ladder, and what happens when it runs out.

No real provider call anywhere here (CLAUDE.md section 3): the SDK call is a
stub that raises what a rate-limited endpoint raises, and `sleep` is injected
so the backoff is asserted rather than spent.
"""
import pytest

from llm_gateway.rate_limit import (
    MAX_ATTEMPTS,
    ProviderExhausted,
    ProviderUnavailable,
    RateLimitExhausted,
    call_with_retry,
    delay_before,
    is_rate_limited,
    is_transient,
)


class FakeResponse:
    def __init__(self, status_code=429, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class SdkRateLimitError(Exception):
    """Shaped like openai.RateLimitError: a status code and a response."""

    def __init__(self, message="Too Many Requests", retry_after=None):
        super().__init__(message)
        self.status_code = 429
        self.response = FakeResponse(headers={"retry-after": retry_after} if retry_after else {})


class TestIsRateLimited:
    def test_a_status_code_attribute_is_enough(self):
        assert is_rate_limited(SdkRateLimitError())

    def test_a_status_code_on_the_response_is_enough(self):
        error = Exception("throttled")
        error.response = FakeResponse(429)

        assert is_rate_limited(error)

    def test_the_class_name_alone_is_enough(self):
        """A gateway wrapper can raise its own RateLimitError carrying no
        status code at all."""
        class RateLimitError(Exception):
            pass

        assert is_rate_limited(RateLimitError("slow down"))

    def test_the_code_in_the_message_is_enough(self):
        assert is_rate_limited(RuntimeError("Error code: 429 - rate limit reached"))

    def test_anything_else_is_not_a_rate_limit(self):
        """A malformed request does not get better by being sent again, so
        misreading one as a 429 would waste the retry ladder on it."""
        error = Exception("Bad Request")
        error.response = FakeResponse(400)

        assert not is_rate_limited(error)
        assert not is_rate_limited(ValueError("model not found"))


class TestBackoff:
    def test_it_doubles(self):
        assert [delay_before(n, SdkRateLimitError()) for n in (2, 3, 4)] == [2.0, 4.0, 8.0]

    def test_the_providers_own_retry_after_wins(self):
        """It knows when its window resets; we are guessing."""
        assert delay_before(2, SdkRateLimitError(retry_after="7")) == 7.0

    def test_an_unparseable_retry_after_falls_back_to_the_ladder(self):
        assert delay_before(3, SdkRateLimitError(retry_after="Wed, 21 Oct 2015 07:28:00 GMT")) == 4.0

    def test_a_huge_retry_after_is_capped(self):
        """A provider asking us to wait an hour is not something a scan can
        honour -- give up and let the partial report be written instead."""
        assert delay_before(2, SdkRateLimitError(retry_after="3600")) == 30.0


class TestCallWithRetry:
    def test_a_call_that_works_is_not_retried(self):
        calls = []

        result = call_with_retry(lambda: calls.append(1) or "ok", sleep=lambda s: None)

        assert result == "ok" and len(calls) == 1

    def test_a_transient_429_clears_on_a_retry(self):
        """The whole point: this used to end the scan."""
        attempts = []
        slept = []

        def send():
            attempts.append(1)
            if len(attempts) < 3:
                raise SdkRateLimitError()
            return "verdict"

        assert call_with_retry(send, sleep=slept.append) == "verdict"
        assert len(attempts) == 3
        assert slept == [2.0, 4.0]

    def test_running_out_of_attempts_raises_its_own_error(self):
        """RateLimitExhausted rather than the SDK's own: the pipeline has to
        tell "the endpoint is throttling us" from "the request was wrong",
        and only the first is something a scan carries on past."""
        slept = []

        def send():
            raise SdkRateLimitError()

        with pytest.raises(RateLimitExhausted) as excinfo:
            call_with_retry(send, sleep=slept.append)

        assert excinfo.value.attempts == MAX_ATTEMPTS
        assert isinstance(excinfo.value.last_error, SdkRateLimitError)
        assert len(slept) == MAX_ATTEMPTS - 1

    def test_anything_that_is_not_a_rate_limit_is_raised_at_once(self):
        slept = []

        def send():
            raise ValueError("model not found")

        with pytest.raises(ValueError):
            call_with_retry(send, sleep=slept.append)

        assert slept == []


class APIConnectionError(Exception):
    """Named like openai.APIConnectionError, which is what a dropped
    connection surfaces as ("Connection error.")."""


class TestTransientFailures:
    """A dropped connection ended two full HA_Benchmark runs in a row, at
    65/384 and 129/384, while the endpoint answered fine seconds later."""

    def test_connection_errors_timeouts_and_5xx_are_transient(self):
        assert is_transient(APIConnectionError("Connection error."))
        error = RuntimeError("bad gateway")
        error.status_code = 502
        assert is_transient(error)
        assert not is_transient(ValueError("model not found"))
        assert not is_transient(SdkRateLimitError())

    def test_a_dropped_connection_is_retried(self):
        slept, attempts = [], []

        def send():
            attempts.append(1)
            if len(attempts) < 3:
                raise APIConnectionError("Connection error.")
            return "verdict"

        assert call_with_retry(send, sleep=slept.append) == "verdict"
        assert len(slept) == 2

    def test_an_exhausted_transient_failure_is_a_provider_exhausted(self):
        """So the pipeline keeps what was verified instead of failing the scan."""
        def send():
            raise APIConnectionError("Connection error.")

        with pytest.raises(ProviderUnavailable) as excinfo:
            call_with_retry(send, sleep=lambda s: None)
        assert isinstance(excinfo.value, ProviderExhausted)
        assert excinfo.value.attempts == MAX_ATTEMPTS

    def test_rate_limit_exhaustion_is_still_its_own_type(self):
        with pytest.raises(RateLimitExhausted) as excinfo:
            call_with_retry(lambda: (_ for _ in ()).throw(SdkRateLimitError()), sleep=lambda s: None)
        assert isinstance(excinfo.value, ProviderExhausted)


class TestProviderIntegration:
    """The retry has to sit inside the provider, so every caller above it --
    verify, translate, the settings page's connection test -- gets it."""

    def provider(self, monkeypatch):
        from llm_gateway.providers.openai_compatible import OpenAICompatibleProvider

        monkeypatch.setattr("llm_gateway.rate_limit.time.sleep", lambda seconds: None)
        return OpenAICompatibleProvider(base_url="http://localhost:1", api_key="not-a-real-key")

    def test_chat_retries_a_429(self, monkeypatch):
        provider = self.provider(monkeypatch)
        attempts = []

        class Message:
            content = '{"reachable": "no"}'

        class Completion:
            choices = [type("Choice", (), {"message": Message})]

        def create(**kwargs):
            attempts.append(kwargs)
            if len(attempts) < 2:
                raise SdkRateLimitError()
            return Completion

        monkeypatch.setattr(provider.client.chat.completions, "create", create)

        assert provider.chat([{"role": "user", "content": "x"}], model="m") == '{"reachable": "no"}'
        assert len(attempts) == 2

    def test_chat_surfaces_an_exhausted_rate_limit(self, monkeypatch):
        provider = self.provider(monkeypatch)

        def create(**kwargs):
            raise SdkRateLimitError()

        monkeypatch.setattr(provider.client.chat.completions, "create", create)

        with pytest.raises(RateLimitExhausted):
            provider.chat([{"role": "user", "content": "x"}], model="m")
