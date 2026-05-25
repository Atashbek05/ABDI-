import time
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class CacheService:
    """In-memory LRU cache for scan results."""

    def __init__(self, max_size: int = 1000, ttl_seconds: int = 300):
        self._cache: Dict[str, Dict] = {}
        self._timestamps: Dict[str, float] = {}
        self._access_order: list = []
        self.max_size = max_size
        self.ttl = ttl_seconds
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Dict]:
        if key not in self._cache:
            self._misses += 1
            return None

        if time.time() - self._timestamps[key] > self.ttl:
            self._evict(key)
            self._misses += 1
            return None

        self._hits += 1
        self._access_order.append(self._access_order.pop(self._access_order.index(key)))
        result = dict(self._cache[key])
        result["cached"] = True
        return result

    def set(self, key: str, value: Dict) -> None:
        if key in self._cache:
            self._access_order.remove(key)
        elif len(self._cache) >= self.max_size:
            oldest = self._access_order.pop(0)
            self._evict(oldest)

        self._cache[key] = value
        self._timestamps[key] = time.time()
        self._access_order.append(key)

    def _evict(self, key: str) -> None:
        self._cache.pop(key, None)
        self._timestamps.pop(key, None)
        if key in self._access_order:
            self._access_order.remove(key)

    def invalidate(self, key: str) -> None:
        self._evict(key)

    def clear(self) -> None:
        self._cache.clear()
        self._timestamps.clear()
        self._access_order.clear()

    @property
    def stats(self) -> Dict:
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / max(1, self._hits + self._misses) * 100, 2),
        }


# Global singleton
scan_cache = CacheService(max_size=2000, ttl_seconds=300)
