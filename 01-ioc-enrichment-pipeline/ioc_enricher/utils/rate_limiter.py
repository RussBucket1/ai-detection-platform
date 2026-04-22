"""Async token bucket rate limiter for provider API calls."""
from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Async token bucket rate limiter with configurable burst capacity.

    Thread-safe for use in asyncio event loops. Sleeps automatically when
    the bucket is depleted and refills at the configured rate.
    """

    def __init__(self, rate: float, burst: int | None = None) -> None:
        """Initialize the rate limiter.

        Args:
            rate: Tokens per second to add to the bucket.
            burst: Maximum token capacity. Defaults to max(1, int(rate * 2)).
        """
        if rate <= 0:
            raise ValueError("rate must be positive")
        self._rate = rate
        self._burst = burst if burst is not None else max(1, int(rate * 2))
        self._tokens: float = float(self._burst)
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        """Add tokens based on elapsed time since last refill, capped at burst."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_refill = now

    async def acquire(self, tokens: int = 1) -> None:
        """Wait until the requested number of tokens are available, then consume them."""
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                sleep_time = deficit / self._rate
                await asyncio.sleep(sleep_time)

    async def __aenter__(self) -> RateLimiter:
        """Acquire one token on context entry."""
        await self.acquire()
        return self

    async def __aexit__(self, *args: object) -> None:
        """No-op on context exit."""

    @property
    def rate(self) -> float:
        """Configured tokens-per-second refill rate."""
        return self._rate

    @property
    def available_tokens(self) -> float:
        """Current available token count (snapshot, not locked)."""
        return self._tokens


class ProviderRateLimiters:
    """Registry of per-provider rate limiters.

    Creates and caches a RateLimiter for each provider name. Unknown providers
    receive a generous 1000 RPS fallback to avoid inadvertent throttling.
    """

    _FALLBACK_RPS = 1000.0

    def __init__(self, provider_rates: dict[str, float]) -> None:
        """Initialize with a mapping of provider name to requests-per-second."""
        self._limiters: dict[str, RateLimiter] = {
            name: RateLimiter(rate) for name, rate in provider_rates.items()
        }

    def get(self, provider: str) -> RateLimiter:
        """Return the rate limiter for a provider, creating a fallback if unknown."""
        if provider not in self._limiters:
            self._limiters[provider] = RateLimiter(self._FALLBACK_RPS)
        return self._limiters[provider]

    def __getitem__(self, provider: str) -> RateLimiter:
        """Subscript access delegates to get()."""
        return self.get(provider)
