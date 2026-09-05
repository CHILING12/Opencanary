"""Explainable, deterministic risk rules for correlated activity."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping

from .models import Aggregate, NormalizedEvent, RiskAssessment, RuleHit


PORT_SCAN_TYPES = {"port_scan_syn", "port_scan_nmap_os", "port_scan_nmap_null", "port_scan_nmap_xmas", "port_scan_nmap_fin"}
DEFAULT_USERS = {"admin", "root", "test", "guest", "user", "administrator"}
WEAK_PASSWORDS = {"", "admin", "123456", "12345678", "password", "password123", "admin1", "root"}


class RiskEngine:
    def __init__(
        self,
        whitelist: Iterable[str] = (),
        sensitive_paths: Iterable[str] = ("/admin", "/login", "/wp-login", "/.env"),
        threat_ips: Iterable[str] = (),
        connection_threshold: int = 20,
        brute_force_threshold: int = 5,
    ):
        self.networks = []
        for item in whitelist:
            try:
                self.networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
        self.sensitive_paths = tuple(str(path).lower() for path in sensitive_paths if str(path))
        self.threat_ips = set(threat_ips)
        if connection_threshold < 1 or brute_force_threshold < 1:
            raise ValueError("risk thresholds must be positive")
        self.connection_threshold = connection_threshold
        self.brute_force_threshold = brute_force_threshold

    def is_whitelisted(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in self.networks)

    def event_tags(self, event: NormalizedEvent) -> set[str]:
        tags = set()
        if event.event_type in PORT_SCAN_TYPES:
            tags.add("port_scan")
        if event.event_type in {"login_attempt", "auth_initiated", "auth_attempt"}:
            tags.add(f"{event.protocol}_brute_force")
        path = self._path(event)
        if path and any(marker in path.lower() for marker in self.sensitive_paths):
            tags.add("sensitive_path")
        if event.src_ip in self.threat_ips:
            tags.add("threat_intelligence")
        if self._weak_credential(event):
            tags.add("weak_credentials")
        return tags

    @staticmethod
    def _path(event: NormalizedEvent) -> str:
        value = event.raw_event.get("logdata", {})
        if isinstance(value, Mapping):
            for key in ("PATH", "path", "URL", "url"):
                if key in value:
                    return str(value[key])
        return ""

    @staticmethod
    def _weak_credential(event: NormalizedEvent) -> bool:
        """Use only the derived classification; plaintext is never re-read."""
        return event.weak_credential

    def assess(self, aggregate: Aggregate, events: Iterable[NormalizedEvent]) -> RiskAssessment:
        event_list = list(events)
        tags = set(aggregate.tags)
        for event in event_list:
            tags.update(self.event_tags(event))
        hits: list[RuleHit] = []
        if len(aggregate.unique_protocols) >= 3:
            hits.append(RuleHit("multi_protocol", 25, "同一来源在 3 种以上协议上产生事件"))
        if "port_scan" in tags:
            hits.append(RuleHit("port_scan", 30, "检测到端口扫描行为"))
        if "weak_credentials" in tags:
            hits.append(RuleHit("weak_credentials", 20, "尝试默认账号或弱口令"))
        if "sensitive_path" in tags:
            hits.append(RuleHit("sensitive_path", 20, "访问敏感 Web 路径"))
        if aggregate.event_count >= self.connection_threshold:
            hits.append(RuleHit("high_volume", 15, f"5 分钟内连接/事件达到 {aggregate.event_count} 次"))
        if aggregate.src_ip in self.threat_ips:
            hits.append(RuleHit("threat_intelligence", 40, "来源命中威胁情报"))
        login_count = sum(
            event.event_type in {"login_attempt", "auth_initiated", "auth_attempt"}
            for event in event_list
        )
        if login_count >= self.brute_force_threshold and "weak_credentials" not in tags:
            hits.append(RuleHit("brute_force", 20, f"短时间内登录尝试达到 {login_count} 次"))
        score = min(100, max(0, sum(hit.points for hit in hits)))
        if self.is_whitelisted(aggregate.src_ip):
            hits.append(RuleHit("whitelist", -30, "来源命中白名单，抵扣 30 分"))
            score = max(0, score - 30)
        severity = "low" if score < 30 else "medium" if score < 60 else "high" if score < 80 else "critical"
        return RiskAssessment(score, severity, tuple(hits))
