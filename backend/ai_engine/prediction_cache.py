"""
PredictionCache
===============
Small TTL+LRU cache for ensemble inference results. Distinct from the
top-level scan cache: this one is keyed on the *feature vector* hash so we
de-duplicate inference even when callers pass slightly different URLs that
produce identical features.

Thread-safety: a single Lock is fine here; ensemble inference is the slow
part and we don't expect heavy concurrent contention.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Iterable, Optional


class PredictionCache:
    def __init__(self, max_size: int = 1024, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl = ttl_seconds
        self._lock = threading.Lock()
        self._store: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()
        self._hits = 0
        self._misses = 0

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def make_key(features: Iterable[float]) -> str:
        """Stable hash for a numeric feature vector."""
        # Rounding keeps near-identical vectors collapsing to one cache key.
        rounded = ",".join(f"{float(x):.4f}" for x in features)
        return hashlib.sha1(rounded.encode("utf-8")).hexdigest()

    # ----------------------------------------------------------------- core
    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            ts, value = entry
            if time.time() - ts > self.ttl:
                self._store.pop(key, None)
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (time.time(), value)
            while len(self._store) > self.max_size:
                self._store.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0

    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self._hits + self._misses
            return {
                "size": len(self._store),
                "max_size": self.max_size,
                "ttl_seconds": self.ttl,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round((self._hits / total * 100), 2) if total else 0.0,
            }


# Module-level singleton.
prediction_cache = PredictionCache(max_size=2048, ttl_seconds=300)
