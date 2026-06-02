from __future__ import annotations

import time
import unittest
from collections import deque
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from backend.app.main import _check_rate_limit, _rate_buckets


class RateLimitingTests(unittest.TestCase):
    def setUp(self) -> None:
        _rate_buckets.clear()

    def test_in_memory_rate_limiting_allows_within_limit(self) -> None:
        client_ip = "192.168.1.100"
        # Allowed limit of 5 requests
        for _ in range(5):
            _check_rate_limit(client_ip, 5)
        
        self.assertEqual(len(_rate_buckets[client_ip]), 5)

    def test_in_memory_rate_limiting_blocks_burst_above_limit(self) -> None:
        client_ip = "192.168.1.101"
        # Burst 5 allowed
        for _ in range(5):
            _check_rate_limit(client_ip, 5)
            
        # 6th should raise 429
        with self.assertRaises(HTTPException) as ctx:
            _check_rate_limit(client_ip, 5)
            
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertEqual(ctx.exception.headers.get("Retry-After"), "60")
        self.assertEqual(ctx.exception.detail["code"], "RATE_LIMIT_EXCEEDED")

    def test_in_memory_rate_limiting_slides_window(self) -> None:
        client_ip = "192.168.1.102"
        # Add 3 timestamps in the past
        now = time.monotonic()
        _rate_buckets[client_ip].append(now - 70)
        _rate_buckets[client_ip].append(now - 65)
        _rate_buckets[client_ip].append(now)
        
        # Check limit of 2; the first two should be cleared as expired
        _check_rate_limit(client_ip, 2)
        
        self.assertEqual(len(_rate_buckets[client_ip]), 2)
        self.assertEqual(_rate_buckets[client_ip][0], now)

    @patch("backend.app.main._redis_client")
    def test_redis_sliding_window_success(self, mock_redis) -> None:
        # Mock Redis client pipeline execution
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe
        # execute() returns results of pipe commands:
        # [zremrangebyscore, zcard, zadd, expire] -> zcard is at index 1
        mock_pipe.execute.return_value = [None, 3, None, None]
        
        client_ip = "192.168.1.103"
        # limit is 5, zcard returned 3, so we are under limit
        _check_rate_limit(client_ip, 5)
        
        mock_redis.pipeline.assert_called_once()
        mock_pipe.zremrangebyscore.assert_called_once()
        mock_pipe.zcard.assert_called_once()
        mock_pipe.zadd.assert_called_once()
        mock_pipe.expire.assert_called_once()
        mock_pipe.execute.assert_called_once()

    @patch("backend.app.main._redis_client")
    def test_redis_sliding_window_exceeded(self, mock_redis) -> None:
        mock_pipe = MagicMock()
        mock_redis.pipeline.return_value = mock_pipe
        # zcard returns 6, limit is 5
        mock_pipe.execute.return_value = [None, 6, None, None]
        
        client_ip = "192.168.1.104"
        with self.assertRaises(HTTPException) as ctx:
            _check_rate_limit(client_ip, 5)
            
        self.assertEqual(ctx.exception.status_code, 429)
        mock_redis.zrem.assert_called_once()


if __name__ == "__main__":
    unittest.main()
