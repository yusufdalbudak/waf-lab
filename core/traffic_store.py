"""In-memory traffic store for real-time dashboard."""
import time
from typing import Dict, List, Optional
from collections import deque
from dataclasses import dataclass, asdict


@dataclass
class TrafficEntry:
    """Single traffic entry for dashboard display."""
    timestamp: float
    method: str
    path: str
    client_ip: str
    user_agent: str
    decision: str  # allow, block, challenge
    reason: str
    score: float
    threat_category: Optional[str]
    status_code: int
    response_time_ms: float
    bytes_sent: int


class TrafficStore:
    """
    In-memory traffic store with circular buffer.
    
    Stores recent traffic entries for dashboard display.
    For production, consider Redis or database backend.
    """
    
    def __init__(self, max_entries: int = 10000):
        """
        Initialize traffic store.
        
        Args:
            max_entries: Maximum number of entries to keep (circular buffer)
        """
        self.max_entries = max_entries
        self.entries: deque = deque(maxlen=max_entries)
        self.stats = {
            "total_requests": 0,
            "total_allowed": 0,
            "total_blocked": 0,
            "total_bytes": 0,
            "by_threat_category": {},
            "by_rule": {},
            "by_ip": {},
            "start_time": time.time()
        }
    
    def add_entry(self, entry: TrafficEntry):
        """Add a traffic entry."""
        self.entries.append(entry)
        self.stats["total_requests"] += 1
        self.stats["total_bytes"] += entry.bytes_sent
        
        if entry.decision == "allow":
            self.stats["total_allowed"] += 1
        else:
            self.stats["total_blocked"] += 1
        
        # Update threat category stats
        if entry.threat_category:
            cat = entry.threat_category
            self.stats["by_threat_category"][cat] = self.stats["by_threat_category"].get(cat, 0) + 1
        
        # Update rule stats
        if entry.reason.startswith("rule:"):
            rule_id = entry.reason.split(":")[1]
            self.stats["by_rule"][rule_id] = self.stats["by_rule"].get(rule_id, 0) + 1
        
        # Update IP stats
        self.stats["by_ip"][entry.client_ip] = self.stats["by_ip"].get(entry.client_ip, 0) + 1
    
    def get_recent_entries(self, limit: int = 100) -> List[Dict]:
        """Get recent traffic entries."""
        return [asdict(entry) for entry in list(self.entries)[-limit:]]
    
    def get_stats(self) -> Dict:
        """Get aggregated statistics."""
        uptime_seconds = time.time() - self.stats["start_time"]
        
        return {
            **self.stats,
            "uptime_seconds": uptime_seconds,
            "requests_per_minute": (self.stats["total_requests"] / uptime_seconds * 60) if uptime_seconds > 0 else 0,
            "block_rate": (self.stats["total_blocked"] / self.stats["total_requests"] * 100) if self.stats["total_requests"] > 0 else 0,
            "current_entries": len(self.entries)
        }
    
    def get_entries_by_ip(self, ip: str, limit: int = 50) -> List[Dict]:
        """Get entries for specific IP."""
        return [
            asdict(entry) for entry in self.entries
            if entry.client_ip == ip
        ][-limit:]
    
    def get_entries_by_decision(self, decision: str, limit: int = 50) -> List[Dict]:
        """Get entries by decision type."""
        return [
            asdict(entry) for entry in self.entries
            if entry.decision == decision
        ][-limit:]
    
    def clear(self):
        """Clear all entries (admin function)."""
        self.entries.clear()
        self.stats = {
            "total_requests": 0,
            "total_allowed": 0,
            "total_blocked": 0,
            "total_bytes": 0,
            "by_threat_category": {},
            "by_rule": {},
            "by_ip": {},
            "start_time": time.time()
        }


# Global traffic store instance
_traffic_store: Optional[TrafficStore] = None


def get_traffic_store() -> TrafficStore:
    """Get or create global traffic store."""
    global _traffic_store
    if _traffic_store is None:
        _traffic_store = TrafficStore(max_entries=10000)
    return _traffic_store

