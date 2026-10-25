"""Geolocation-based threat mapping."""
from __future__ import annotations
import logging
from typing import Any
logger = logging.getLogger(__name__)

class GeoMapper:
    def map_ip(self, ip: str) -> dict[str, Any]:
        # mock fallback; real geoip would use geoip2 db
        return {"ip": ip, "country": "unknown", "lat": 0.0, "lon": 0.0}

    def map_many(self, ips: list[str]) -> list[dict[str, Any]]:
        return [self.map_ip(i) for i in ips]
