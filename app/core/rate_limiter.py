"""
In-memory Sliding Window Rate Limiter for QShield.
Provides thread-safe request throttling for resource-intensive operations
(QR decoding, URL analysis, threat intelligence lookups, redirect tracing, PDF exports).
Configurable via application configuration and returns standard HTTP 429 responses.
"""
import time
import threading
from collections import deque
from functools import wraps
from typing import Dict, Tuple, Optional
from flask import request, jsonify, current_app


class SlidingWindowRateLimiter:
    """
    Thread-safe in-memory sliding window rate limiter.
    Maintains a ring of request timestamps per client key.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._storage: Dict[str, deque] = {}

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        """
        Check if request under `key` is allowed within `window_seconds`.
        Returns (is_allowed: bool, retry_after_seconds: int).
        """
        now = time.time()
        window_start = now - window_seconds

        with self._lock:
            if key not in self._storage:
                self._storage[key] = deque()

            bucket = self._storage[key]

            # Evict timestamps outside the current window
            while bucket and bucket[0] <= window_start:
                bucket.popleft()

            # Check if threshold is reached
            if len(bucket) >= max_requests:
                oldest = bucket[0]
                retry_after = max(1, int(oldest + window_seconds - now))
                return False, retry_after

            # Record this request
            bucket.append(now)
            return True, 0

    def reset(self):
        """Clear all recorded rate limit state (used in testing)."""
        with self._lock:
            self._storage.clear()


# Global singleton rate limiter instance
_limiter = SlidingWindowRateLimiter()


def get_limiter() -> SlidingWindowRateLimiter:
    """Returns the shared rate limiter instance."""
    return _limiter


def get_client_ip() -> str:
    """Extracts client IP for rate limiting with fallback."""
    # If reverse proxy configured, can use X-Forwarded-For; default to remote_addr
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'


def rate_limit(limit_config_key: str, default_limit: int = 30, window_seconds: int = 60):
    """
    Flask route decorator to enforce rate limiting on sensitive endpoints.
    Reads limit from `current_app.config[limit_config_key]` with fallback to `default_limit`.
    If `current_app.config['RATELIMIT_ENABLED']` is False, bypasses rate limiting.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            enabled = current_app.config.get('RATELIMIT_ENABLED', True)
            if not enabled:
                return f(*args, **kwargs)

            limit = current_app.config.get(limit_config_key, default_limit)
            window = current_app.config.get('RATELIMIT_DEFAULT_WINDOW', window_seconds)

            client_key = f"{request.endpoint}:{get_client_ip()}"
            allowed, retry_after = _limiter.is_allowed(client_key, limit, window)

            if not allowed:
                response = jsonify({
                    "success": False,
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "message": f"Rate limit exceeded. Maximum {limit} requests per {window}s allowed for this endpoint. Please retry after {retry_after} seconds.",
                    "retry_after": retry_after
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(retry_after)
                return response

            return f(*args, **kwargs)
        return decorated_function
    return decorator
