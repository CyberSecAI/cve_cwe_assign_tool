# src/utils/rate_limiter.py

import time
import asyncio
from typing import List, Any, Callable, TypeVar, Optional
from dataclasses import dataclass
import logging
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

T = TypeVar('T')

@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    requests_per_minute: int = 50  # Anthropic's default limit
    burst_limit: int = 5
    retry_delay: float = 2.0
    max_retries: int = 3
    batch_size: int = 10

class TokenBucket:
    """Token bucket rate limiter"""
    def __init__(self, rate: float, capacity: int):
        self.rate = rate  # tokens per second
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        
    def _add_tokens(self):
        now = time.time()
        time_passed = now - self.last_update
        new_tokens = time_passed * self.rate
        self.tokens = min(self.capacity, self.tokens + new_tokens)
        self.last_update = now
        
    async def acquire(self):
        while self.tokens <= 0:
            self._add_tokens()
            if self.tokens <= 0:
                await asyncio.sleep(1.0 / self.rate)
        self.tokens -= 1
        return True

class ApiRateLimiter:
    """Rate limiter for API calls with retry logic"""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.token_bucket = TokenBucket(
            rate=config.requests_per_minute / 60,
            capacity=config.burst_limit
        )
        self._request_times: List[float] = []
        
    async def process_batch(
        self,
        items: List[T],
        process_func: Callable[[T], Any],
        error_handler: Optional[Callable[[Exception, T], Any]] = None
    ) -> List[Any]:
        """Process items in batches with rate limiting"""
        results = []
        
        # Process in batches
        for i in range(0, len(items), self.config.batch_size):
            batch = items[i:i + self.config.batch_size]
            batch_results = await self._process_batch_with_retries(
                batch, process_func, error_handler
            )
            results.extend(batch_results)
            
            # Log progress
            logger.info(
                f"Processed batch {i//self.config.batch_size + 1}/"
                f"{(len(items) + self.config.batch_size - 1)//self.config.batch_size}"
            )
            
        return results
    
    async def _process_batch_with_retries(
        self,
        batch: List[T],
        process_func: Callable[[T], Any],
        error_handler: Optional[Callable[[Exception, T], Any]]
    ) -> List[Any]:
        """Process a batch of items with retry logic"""
        results = []
        
        for item in batch:
            retry_count = 0
            while retry_count < self.config.max_retries:
                try:
                    # Wait for rate limit
                    await self.token_bucket.acquire()
                    
                    # Process item
                    if asyncio.iscoroutinefunction(process_func):
                        result = await process_func(item)
                    else:
                        # If it's a regular function, run it in the executor
                        result = await asyncio.get_event_loop().run_in_executor(
                            None, process_func, item
                        )
                    
                    results.append(result)
                    break
                    
                except Exception as e:
                    retry_count += 1
                    if retry_count == self.config.max_retries:
                        if error_handler:
                            results.append(error_handler(e, item))
                        else:
                            logger.error(f"Failed to process item after {retry_count} retries: {e}")
                            results.append(None)
                    else:
                        delay = self.config.retry_delay * (2 ** (retry_count - 1))  # Exponential backoff
                        logger.warning(f"Retrying after {delay:.1f}s. Error: {e}")
                        await asyncio.sleep(delay)
                        
        return results
    
    @asynccontextmanager
    async def batch_context(self):
        """Context manager for batch processing"""
        try:
            yield self
        finally:
            # Clean up request history older than 1 minute
            now = time.time()
            self._request_times = [t for t in self._request_times if now - t <= 60]
            
    def get_stats(self) -> dict:
        """Get current rate limiter statistics"""
        now = time.time()
        recent_requests = len([t for t in self._request_times if now - t <= 60])
        return {
            "requests_last_minute": recent_requests,
            "tokens_available": self.token_bucket.tokens,
            "config": {
                "requests_per_minute": self.config.requests_per_minute,
                "burst_limit": self.config.burst_limit,
                "batch_size": self.config.batch_size
            }
        }
# Example usage:
"""
config = RateLimitConfig(
    requests_per_minute=50,
    burst_limit=5,
    batch_size=10
)

async def process_contexts(entries):
    rate_limiter = ApiRateLimiter(config)
    
    async def generate_context(entry):
        # Your context generation logic here
        return context
        
    def handle_error(error, entry):
        logger.error(f"Failed to process entry {entry.ID}: {error}")
        return None
    
    async with rate_limiter.batch_context():
        results = await rate_limiter.process_batch(
            entries,
            generate_context,
            handle_error
        )
    return results
"""