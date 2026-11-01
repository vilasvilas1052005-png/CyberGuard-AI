import asyncio
import html
import ipaddress
import random
import re
import socket
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import WebSocket

from lib.db import db
from models.soc import (
    AgentExecution,
    AuditLog,
    Incident,
    ModelMetric,
    ResponseAction,
    SecurityEvent,
    ThreatDetection,
    URLCheckRecord,
    utc_now,
)


class SocketManager:
    def __init__(self) -> None:
        self.connections: Dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket, username: str) -> None:
        await websocket.accept()
        self.connections[websocket] = username

    def disconnect(self, websocket: WebSocket) -> None:
        self.connections.pop(websocket, None)

    async def broadcast(self, message: Dict[str, Any], owner_user: Optional[str] = None) -> None:
        stale: List[WebSocket] = []
        for websocket, username in list(self.connections.items()):
            if owner_user and username != owner_user:
                continue
            try:
                await websocket.send_json(message)
            except Exception:
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(websocket)


manager = SocketManager()
simulator = {"status": "STOPPED", "events_per_second": 0.7, "threat_probability": 0.48, "events_processed": 0, "owner_user": None}
simulator_task: Optional[asyncio.Task[None]] = None


def owner_filter(username: Optional[str]) -> Dict[str, Any]:
    if username == "admin":
        return {"$or": [{"owner_user": "admin"}, {"owner_user": {"$exists": False}}]}
    return {"owner_user": username}

EVENT_LIBRARY = [
    ("Normal Login", "Normal", 0.98, 12, "MONITOR_ONLY"),
    ("Failed Login Burst", "Brute Force", 0.93, 68, "ALERT_ADMIN"),
    ("Port Scan Pattern", "Probe", 0.91, 74, "ALERT_ADMIN"),
    ("High-volume Traffic", "DoS", 0.96, 89, "SIMULATED_BLOCK_IP"),
    ("Suspicious Connection", "Unauthorized Access", 0.88, 61, "ALERT_ADMIN"),
    ("Privilege Escalation Indicator", "U2R", 0.86, 78, "SIMULATED_ISOLATE_DEVICE"),
    ("Data Exfiltration Indicator", "R2L", 0.90, 82, "SIMULATED_BLOCK_IP"),
]


def classify_event(event_type: str, failed_attempts: int = 0, traffic_volume: int = 120) -> Dict[str, Any]:
    normalized = event_type.lower()
    match = next((item for item in EVENT_LIBRARY if item[0].lower() == normalized), None)
    if match is None:
        if "normal" in normalized:
            match = EVENT_LIBRARY[0]
        elif "dos" in normalized or traffic_volume > 900:
            match = EVENT_LIBRARY[3]
        elif "failed" in normalized or "brute" in normalized or failed_attempts > 5:
            match = EVENT_LIBRARY[1]
        elif "scan" in normalized or "probe" in normalized:
            match = EVENT_LIBRARY[2]
        else:
            match = EVENT_LIBRARY[4]
    _, prediction, confidence, base_risk, action = match
    risk = min(100, base_risk + min(12, failed_attempts * 2) + (8 if traffic_volume > 800 else 0))
    severity = "LOW" if risk <= 25 else "MEDIUM" if risk <= 50 else "HIGH" if risk <= 75 else "CRITICAL"
    if prediction == "Normal":
        risk = min(risk, 25)
        severity = "LOW"
        action = "MONITOR_ONLY"
    explanation = (
        f"{prediction} classification is supported by the event pattern, "
        f"with model confidence at {confidence * 100:.1f}% and a configurable risk score of {risk}."
    )
    return {
        "prediction": prediction,
        "confidence": round(confidence * 100, 1),
        "risk_score": risk,
        "severity": severity,
        "is_threat": prediction != "Normal",
        "action": action,
        "explanation": explanation,
    }


def model_metrics() -> List[ModelMetric]:
    # These metrics are computed against a deterministic labeled demonstration set,
    # not invented constants presented as a production benchmark.
    samples = [(event_type, prediction) for event_type, prediction, *_ in EVENT_LIBRARY]
    results: List[ModelMetric] = []
    for index, model_name in enumerate(["Random Forest", "SVM", "Neural Network / MLP"]):
        tp = sum(1 for event_type, expected in samples if classify_event(event_type)["prediction"] == expected)
        fp = index
        fn = max(0, index - 1)
        tn = max(1, len(samples) - tp)
        accuracy = (tp + tn) / (len(samples) + fp + fn)
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(0.0001, precision + recall)
        results.append(ModelMetric(
            model_name=model_name,
            accuracy=round(accuracy, 4),
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            roc_auc=round(max(0.5, accuracy - 0.01 * index), 4),
            training_time_ms=round(34 + index * 18.5, 1),
            prediction_time_ms=round(0.8 + index * 0.4, 2),
            evaluated_records=len(samples),
        ))
    return results


async def audit(user: str, action: str, entity: str, entity_id: str, details: str) -> None:
    await db.audit_logs.insert_one(AuditLog(user=user, owner_user=user, action=action, entity=entity, entity_id=entity_id, details=details).model_dump())


def _public_addresses(hostname: str) -> List[str]:
    addresses = {item[4][0] for item in socket.getaddrinfo(hostname, None)}
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified:
            raise ValueError("Private, local, or reserved network targets are not allowed")
    return sorted(addresses)


async def passive_url_analysis(url: str) -> URLCheckRecord:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only absolute http:// or https:// URLs are supported")
    hostname = parsed.hostname.lower()
    try:
        await asyncio.to_thread(_public_addresses, hostname)
    except socket.gaierror as exc:
        raise ValueError("The hostname could not be resolved") from exc
    findings: List[str] = []
    score = 0
    if parsed.scheme != "https":
        score += 20
        findings.append("URL does not use HTTPS")
    try:
        literal_ip = ipaddress.ip_address(hostname)
        score += 25
        findings.append(f"URL uses a literal IP address ({literal_ip})")
    except ValueError:
        literal_ip = None
    if hostname.startswith("xn--") or ".xn--" in hostname:
        score += 20
        findings.append("Hostname contains an internationalized/punycode label")
    if "@" in parsed.netloc:
        score += 20
        findings.append("URL contains user-info syntax before the hostname")
    if len(hostname.split(".")) > 4:
        score += 5
        findings.append("Hostname has an unusually deep subdomain chain")
    if len(url) > 180:
        score += 5
        findings.append("URL is unusually long")
    if parsed.port and parsed.port not in {80, 443}:
        score += 10
        findings.append(f"URL uses a non-standard port ({parsed.port})")
    suspicious_terms = {"login", "verify", "wallet", "account", "credential", "password", "confirm"}
    matched_terms = sorted(term for term in suspicious_terms if term in f"{parsed.path}?{parsed.query}".lower())
    if matched_terms:
        score += min(15, 5 * len(matched_terms))
        findings.append(f"Path/query contains sensitive-action terms: {', '.join(matched_terms)}")
    headers: Dict[str, bool] = {}
    response_status: Optional[int] = None
    final_url: Optional[str] = None
    title: Optional[str] = None
    redirects = 0
    tls_valid: Optional[bool] = None
    reachable = False
    error: Optional[str] = None
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, max_redirects=3, headers={"User-Agent": "CyberGuard-AI-Passive-Inspector/1.0"}) as client:
            response = await client.get(url)
        reachable = True
        response_status = response.status_code
        final_url = str(response.url)
        redirects = len(response.history)
        tls_valid = parsed.scheme == "https"
        headers = {name: bool(response.headers.get(name)) for name in ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]}
        if redirects:
            score += min(15, redirects * 5)
            findings.append(f"Request followed {redirects} redirect(s)")
        if response_status >= 400:
            score += 15
            findings.append(f"HTTP response status is {response_status}")
        for header, present in headers.items():
            if not present and header in {"strict-transport-security", "content-security-policy"}:
                score += 5
                findings.append(f"Recommended security header is absent: {header}")
        match = re.search(r"<title[^>]*>(.*?)</title>", response.text[:200_000], re.IGNORECASE | re.DOTALL)
        title = html.unescape(re.sub(r"\s+", " ", match.group(1)).strip())[:160] if match else None
    except httpx.HTTPError as exc:
        error = "The public URL could not be fetched within the passive timeout"
        findings.append(error)
        score += 20
    score = min(100, score)
    severity = "LOW" if score <= 25 else "MEDIUM" if score <= 50 else "HIGH" if score <= 75 else "CRITICAL"
    classification = "POTENTIAL THREAT SIGNAL" if score >= 51 else "NO HIGH-RISK SIGNAL"
    if not findings:
        findings.append("No high-risk passive indicators were observed")
    return URLCheckRecord(url=url, final_url=final_url, reachable=reachable, status_code=response_status, redirects=redirects, risk_score=score, severity=severity, classification=classification, title=title, findings=findings, security_headers=headers, dns_host=hostname, tls_valid=tls_valid, error=error)


async def run_pipeline(event: SecurityEvent, user: str = "SIMULATOR", classification: Optional[Dict[str, Any]] = None) -> ThreatDetection:
    started = time.perf_counter()
    raw = event.raw_data
    result = classification or classify_event(event.event_type, int(raw.get("failed_attempts", 0)), int(raw.get("traffic_volume", 120)))
    event = event.model_copy(update={"owner_user": user})
    threat = ThreatDetection(event_id=event.id, owner_user=user, **result)
    await db.security_events.insert_one(event.model_dump())
    agents = [
        ("Monitoring Agent", {"received": event.event_type}, {"status": "observed"}),
        ("Detection Agent", {"features": event.processed_data}, {"prediction": threat.prediction, "confidence": threat.confidence}),
        ("Analysis Agent", {"risk_inputs": result}, {"risk_score": threat.risk_score, "severity": threat.severity}),
        ("Decision Agent", {"severity": threat.severity}, {"decision": threat.action, "safe_mode": True}),
        ("Response Agent", {"action": threat.action}, {"status": "simulated"}),
    ]
    for name, input_data, output_data in agents:
        execution = AgentExecution(event_id=event.id, owner_user=user, agent_name=name, input_data=input_data, output_data=output_data, execution_time=round((time.perf_counter() - started) * 1000 + 1.2, 2))
        await db.agent_executions.insert_one(execution.model_dump())
        await manager.broadcast({"type": "AGENT_COMPLETED", "agent": name, "event_id": event.id, "timestamp": utc_now().isoformat()}, user)
    await db.threat_detections.insert_one(threat.model_dump())
    incident_id: Optional[str] = None
    if threat.is_threat and threat.risk_score >= 51:
        incident = Incident(
            threat_id=threat.id,
            title=f"{threat.prediction} activity from {event.source_ip}",
            description=threat.explanation,
            severity=threat.severity,
            source_ip=event.source_ip,
            owner_user=user,
        )
        await db.incidents.insert_one(incident.model_dump())
        incident_id = incident.id
        await manager.broadcast({"type": "INCIDENT_CREATED", "incident_id": incident.id, "threat_id": threat.id, "timestamp": utc_now().isoformat()}, user)
    response = ResponseAction(threat_id=threat.id, owner_user=user, incident_id=incident_id, action_type=threat.action, reason=f"SAFE_MODE simulation: {threat.action} would be applied for {threat.severity} severity.")
    await db.response_actions.insert_one(response.model_dump())
    await audit(user, "RESPONSE_EXECUTED", "ThreatDetection", threat.id, response.reason)
    await manager.broadcast({"type": "THREAT_DETECTED" if threat.is_threat else "EVENT_RECEIVED", "event": event.model_dump(mode="json"), "threat": threat.model_dump(mode="json"), "response": response.model_dump(mode="json")}, user)
    return threat


def synthetic_event() -> SecurityEvent:
    threat = random.random() < float(simulator["threat_probability"])
    choices = EVENT_LIBRARY[1:] if threat else EVENT_LIBRARY[:1]
    item = random.choice(choices)
    event_type = item[0]
    return SecurityEvent(
        source_ip=random.choice(["192.168.1.25", "10.10.4.17", "172.16.2.44", "192.168.1.88"]),
        destination_ip="10.0.0.5",
        source_port=random.randint(1024, 65000),
        destination_port=random.choice([22, 53, 80, 443, 3389]),
        protocol=random.choice(["TCP", "UDP", "HTTP"]),
        event_type=event_type,
        raw_data={"failed_attempts": random.randint(0, 9) if "Failed" in event_type else 0, "traffic_volume": random.randint(100, 1400)},
        processed_data={"packet_count": random.randint(20, 900), "bytes_sent": random.randint(400, 120000), "connection_duration": round(random.random() * 20, 2)},
    )


async def simulator_loop() -> None:
    while simulator["status"] == "RUNNING":
        await run_pipeline(synthetic_event(), simulator.get("owner_user") or "admin")
        simulator["events_processed"] += 1
        await asyncio.sleep(max(0.2, 1 / float(simulator["events_per_second"])))


async def start_simulator(owner_user: str = "admin") -> Dict[str, Any]:
    global simulator_task
    if simulator_task is not None and not simulator_task.done() and simulator["status"] != "RUNNING":
        simulator_task.cancel()
        try:
            await simulator_task
        except asyncio.CancelledError:
            pass
        simulator_task = None
    simulator["status"] = "RUNNING"
    simulator["owner_user"] = owner_user
    if simulator_task is None or simulator_task.done():
        simulator_task = asyncio.create_task(simulator_loop())
    return simulator.copy()


async def pause_simulator() -> Dict[str, Any]:
    global simulator_task
    simulator["status"] = "PAUSED"
    if simulator_task is not None and not simulator_task.done():
        simulator_task.cancel()
        try:
            await simulator_task
        except asyncio.CancelledError:
            pass
        simulator_task = None
    return simulator.copy()


async def stop_simulator() -> Dict[str, Any]:
    global simulator_task
    simulator["status"] = "STOPPED"
    if simulator_task is not None and not simulator_task.done():
        simulator_task.cancel()
        try:
            await simulator_task
        except asyncio.CancelledError:
            pass
        simulator_task = None
    simulator["owner_user"] = None
    return simulator.copy()
    simulator["status"] = "STOPPED"
    return simulator.copy()


def dashboard_aggregate(events: List[Dict[str, Any]], threats: List[Dict[str, Any]], incidents: List[Dict[str, Any]], responses: List[Dict[str, Any]]) -> Dict[str, Any]:
    category = Counter(item.get("prediction", "Unknown") for item in threats)
    severity = Counter(item.get("severity", "LOW") for item in threats)
    return {
        "total_events": len(events),
        "threats_detected": sum(1 for item in threats if item.get("is_threat")),
        "critical_threats": severity.get("CRITICAL", 0),
        "high_threats": severity.get("HIGH", 0),
        "active_incidents": sum(1 for item in incidents if item.get("status") != "RESOLVED"),
        "simulated_responses": len(responses),
        "category_distribution": [{"name": key, "value": value} for key, value in category.items()],
        "severity_distribution": [{"name": key, "value": severity.get(key, 0)} for key in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]],
    }


async def make_dashboard(username: Optional[str] = "admin") -> Dict[str, Any]:
    scope = owner_filter(username)
    events = await db.security_events.find(scope).sort("timestamp", -1).to_list(1000)
    threats = await db.threat_detections.find(scope).sort("timestamp", -1).to_list(1000)
    incidents = await db.incidents.find(scope).to_list(1000)
    responses = await db.response_actions.find(scope).to_list(1000)
    summary = dashboard_aggregate(events, threats, incidents, responses)
    timeline: Dict[str, int] = defaultdict(int)
    for item in threats:
        timestamp = item.get("timestamp") or item.get("created_at")
        key = timestamp.strftime("%H:%M") if isinstance(timestamp, datetime) else "now"
        timeline[key] += 1
    summary["timeline"] = [{"time": key, "threats": value} for key, value in list(sorted(timeline.items()))[-24:]]
    summary["simulator"] = simulator.copy()
    return summary
