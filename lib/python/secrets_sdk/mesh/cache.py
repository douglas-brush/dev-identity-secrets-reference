"""TTL-based in-memory cache for secrets with max-size eviction.

Thread-safe implementation using a simple lock. Eviction uses LRU
strategy when max_size is reached.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from typing import Generic, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class _CacheEntry(Generic[T]):
    """Internal cache entry with value and expiration timestamp."""

    __slots__ = ("value", "expires_at", "created_at")

    def __init__(self, value: T, ttl_seconds: float) -> None:
        now = time.monotonic()
        self.value = value
        self.created_at = now
        self.expires_at = now + ttl_seconds

    @property
    def is_expired(self) -> bool:
        return time.monotonic() >= self.expires_at


class TTLCache(Generic[T]):
    """TTL-based in-memory cache with max-size LRU eviction.

    Args:
        default_ttl: Default time-to-live in seconds for cached entries.
        max_size: Maximum number of entries. 0 means unlimited.
    """

    def __init__(self, default_ttl: float = 300.0, max_size: int = 1000) -> None:
        if default_ttl <= 0:
            raise ValueError("default_ttl must be positive")
        if max_size < 0:
            raise ValueError("max_size must be non-negative")
        self._default_ttl = default_ttl
        self._max_size = max_size
        self._data: OrderedDict[str, _CacheEntry[T]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    @property
    def default_ttl(self) -> float:
        """Default TTL in seconds."""
        return self._default_ttl

    @property
    def max_size(self) -> int:
        """Maximum cache size."""
        return self._max_size

    @property
    def hits(self) -> int:
        """Total cache hits."""
        return self._hits

    @property
    def misses(self) -> int:
        """Total cache misses."""
        return self._misses

    @property
    def hit_rate(self) -> float:
        """Cache hit rate as a ratio (0.0 to 1.0)."""
        total = self._hits + self._misses
        if total == 0:
            return 0.0
        return self._hits / total

    def get(self, key: str) -> T | None:
        """Get a value from the cache.

        Returns None on miss or expired entry.
        """
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                self._misses += 1
                return None
            if entry.is_expired:
                del self._data[key]
                self._misses += 1
                return None
            # Move to end for LRU ordering
            self._data.move_to_end(key)
            self._hits += 1
            return entry.value

    def put(self, key: str, value: T, ttl: float | None = None) -> None:
        """Store a value in the cache.

        Args:
            key: Cache key.
            value: Value to store.
            ttl: TTL in seconds. Uses default_ttl if None.
        """
        effective_ttl = ttl if ttl is not None else self._default_ttl
        if effective_ttl <= 0:
            return  # Don't cache zero/negative TTL items

        with self._lock:
            # Remove if exists to refresh position
            if key in self._data:
                del self._data[key]
            # Evict LRU entries if at max capacity
            if self._max_size > 0:
                while len(self._data) >= self._max_size:
                    evicted_key, _ = self._data.popitem(last=False)
                    logger.debug("Cache evicted key: %s", evicted_key)
            self._data[key] = _CacheEntry(value, effective_ttl)

    def invalidate(self, key: str) -> bool:
        """Remove a specific key from the cache.

        Returns True if the key was present.
        """
        with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False

    def clear(self) -> int:
        """Remove all entries. Returns the number of entries removed."""
        with self._lock:
            count = len(self._data)
            self._data.clear()
            return count

    def size(self) -> int:
        """Return the current number of (possibly expired) entries."""
        return len(self._data)

    def purge_expired(self) -> int:
        """Remove all expired entries. Returns the count removed."""
        with self._lock:
            expired_keys = [k for k, v in self._data.items() if v.is_expired]
            for k in expired_keys:
                del self._data[k]
            return len(expired_keys)

    def reset_stats(self) -> None:
        """Reset hit/miss counters."""
        self._hits = 0
        self._misses = 0

    def stats(self) -> dict[str, float | int]:
        """Return cache statistics."""
        return {
            "size": self.size(),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self.hit_rate,
            "default_ttl": self._default_ttl,
        }
