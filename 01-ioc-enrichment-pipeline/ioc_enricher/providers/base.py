"""Abstract base provider with retry, backoff, and latency tracking."""
from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

import aiohttp

from ioc_enricher.models.ioc import IOC, IOCType, ProviderResult
from ioc_enricher.utils.logger import get_logger
from ioc_enricher.utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    pass

_log = get_logger(__name__)


class BaseProvider(ABC):
    """Abstract enrichment provider with retry logic, rate limiting, and latency tracking.

    Subclasses must implement _enrich_impl() with the provider-specific API call.
    The public enrich() method handles all cross-cutting concerns.
    """

    supported_types: ClassVar[set[IOCType]] = set()
    _RETRYABLE_STATUS: ClassVar[frozenset[int]] = frozenset({429, 500, 502, 503, 504})

    def __init__(
        self,
        api_key: str,
        base_url: str,
        rate_limiter: RateLimiter,
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize the provider with credentials and operational parameters."""
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._rate_limiter = rate_limiter
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._max_retries = max_retries

    @property
    def name(self) -> str:
        """Provider name derived from the class name (lowercase, stripped of 'provider')."""
        cls_name = type(self).__name__.lower()
        return cls_name.replace("provider", "")

    def supports(self, ioc: IOC) -> bool:
        """Return True if this provider can enrich the given IOC type."""
        return ioc.ioc_type in self.supported_types

    async def enrich(self, ioc: IOC, session: aiohttp.ClientSession) -> ProviderResult:
        """Enrich an IOC with retry logic, rate limiting, and latency tracking.

        Returns ProviderResult with success=False for unsupported types or after
        exhausting retries. Exponential backoff: base=1s, multiplier=2x, cap=30s.
        """
        if not self.supports(ioc):
            return ProviderResult(
                provider=self.name,
                success=False,
                latency_ms=0.0,
                data={},
                error=f"Unsupported IOC type: {ioc.ioc_type.value}",
            )

        last_error: str = ""
        backoff = 1.0

        for attempt in range(self._max_retries + 1):
            await self._rate_limiter.acquire()
            start = time.monotonic()
            try:
                data = await self._enrich_impl(ioc, session)
                latency_ms = (time.monotonic() - start) * 1000
                return ProviderResult(
                    provider=self.name,
                    success=True,
                    latency_ms=latency_ms,
                    data=data,
                )
            except aiohttp.ClientResponseError as exc:
                latency_ms = (time.monotonic() - start) * 1000
                last_error = f"HTTP {exc.status}: {exc.message}"
                if exc.status in self._RETRYABLE_STATUS:
                    _log.warning(
                        "provider_retryable_error",
                        provider=self.name,
                        attempt=attempt + 1,
                        max_retries=self._max_retries,
                        status=exc.status,
                        ioc=ioc.value,
                    )
                    if attempt < self._max_retries:
                        await asyncio.sleep(min(backoff, 30.0))
                        backoff *= 2
                    continue
                _log.error(
                    "provider_fatal_error",
                    provider=self.name,
                    status=exc.status,
                    ioc=ioc.value,
                )
                return ProviderResult(
                    provider=self.name,
                    success=False,
                    latency_ms=latency_ms,
                    data={},
                    error=last_error,
                )
            except asyncio.TimeoutError:
                latency_ms = (time.monotonic() - start) * 1000
                last_error = "Request timed out"
                _log.warning(
                    "provider_timeout",
                    provider=self.name,
                    attempt=attempt + 1,
                    max_retries=self._max_retries,
                    ioc=ioc.value,
                )
                if attempt < self._max_retries:
                    await asyncio.sleep(min(backoff, 30.0))
                    backoff *= 2
                continue
            except Exception as exc:  # noqa: BLE001
                latency_ms = (time.monotonic() - start) * 1000
                last_error = f"Unexpected error: {type(exc).__name__}: {exc}"
                _log.exception(
                    "provider_unexpected_error",
                    provider=self.name,
                    ioc=ioc.value,
                    error=str(exc),
                )
                return ProviderResult(
                    provider=self.name,
                    success=False,
                    latency_ms=latency_ms,
                    data={},
                    error=last_error,
                )

        return ProviderResult(
            provider=self.name,
            success=False,
            latency_ms=0.0,
            data={},
            error=f"Max retries ({self._max_retries}) exceeded. Last error: {last_error}",
        )

    @abstractmethod
    async def _enrich_impl(self, ioc: IOC, session: aiohttp.ClientSession) -> dict:
        """Provider-specific enrichment logic. Must return a normalized data dict."""