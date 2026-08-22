import time
from collections import defaultdict, deque

class RateLimiter:
    def __init__(self, max_requests: int = 40, time_window: int = 10):
        self.requests = defaultdict(deque)
        self.max_requests = max_requests
        self.time_window = time_window

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        q = self.requests[ip]
        while q and q[0] < now - self.time_window:
            q.popleft()
        if len(q) >= self.max_requests:
            return False
        q.append(now)
        return True
