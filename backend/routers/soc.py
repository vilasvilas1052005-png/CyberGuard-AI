import csv
import io
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import Response

from lib.db import db
from models.soc import (
    DetectionRequest,
    DatasetRecord,
    IncidentUpdate,
    ResponseRequest,
    SecurityEvent,
    SettingUpdate,
    SimulationSettings,
    URLCheckRecord,
    URLCheckRequest,
)
from routers.auth import current_user, websocket_user
from services.soc_service import (
    audit,
    classify_event,
    manager,
    make_dashboard,
    model_metrics,
    run_pipeline,
    simulator,
    start_simulator,
    stop_simulator,
    passive_url_analysis,
    pause_simulator,
    owner_filter,
)

router = APIRouter(tags=["soc"])
url_check_rate_limit: Dict[str, float] = {}


def require_writer(user: dict) -> None:
    if user.get("role") not in {"ADMIN", "ANALYST"}:
        raise HTTPException(status_code=403, detail="Analyst or admin role required")


async def list_docs(collection: Any, limit: int = 100, username: str | None = None) -> List[Dict[str, Any]]:
    scope = owner_filter(username) if username else {}
    return await collection.find(scope, {"_id": 0}).sort([("timestamp", -1), ("created_at", -1)]).to_list(limit)


@router.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "safe_mode": "true", "service": "cyberguard-soc"}


@router.get("/datasets", response_model=List[DatasetRecord])
async def datasets(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    return await list_docs(db.datasets, 50, user.get("username"))


@router.post("/datasets/upload", response_model=DatasetRecord)
async def upload_dataset(request: Request, file: UploadFile = File(...)) -> DatasetRecord:
    user = await current_user(request)
    if user.get("role") not in {"ADMIN", "ANALYST"}:
        raise HTTPException(status_code=403, detail="Analyst or admin role required")
    filename = file.filename or "uploaded-dataset.csv"
    if not filename.lower().endswith((".csv", ".txt")):
        raise HTTPException(status_code=415, detail="Upload an NSL-KDD-style CSV or TXT file")
    raw = await file.read()
    if len(raw) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Dataset is limited to 8 MB for this local demo")
    text = raw.decode("utf-8", errors="replace")
    rows = [row for row in csv.reader(io.StringIO(text)) if any(cell.strip() for cell in row)]
    if not rows:
        raise HTTPException(status_code=422, detail="The uploaded dataset is empty")
    known_headers = {"duration", "protocol_type", "service", "flag", "label", "class", "attack"}
    header_present = any(cell.strip().lower() in known_headers for cell in rows[0])
    columns = [cell.strip() or f"feature_{index + 1:02d}" for index, cell in enumerate(rows[0])] if header_present else [f"feature_{index + 1:02d}" for index in range(len(rows[0]))]
    data_rows = rows[1:] if header_present else rows
    width = len(columns)
    normalized_rows = [row[:width] + [""] * max(0, width - len(row)) for row in data_rows]
    labels = [row[-1].strip() or "unknown" for row in normalized_rows]
    categorical_columns = 0
    for column_index in range(max(0, width - 1)):
        values = [row[column_index].strip() for row in normalized_rows[:100] if row[column_index].strip()]
        if values:
            try:
                [float(value) for value in values]
            except ValueError:
                categorical_columns += 1
    missing_values = sum(1 for row in normalized_rows for cell in row if not cell.strip())
    duplicate_rows = len(normalized_rows) - len({tuple(row) for row in normalized_rows})
    preview = [dict(zip(columns, row)) for row in normalized_rows[:5]]
    record = DatasetRecord(
        filename=filename,
        format="NSL-KDD-style CSV/TXT",
        records=len(normalized_rows),
        features=max(0, width - 1),
        classes=sorted(set(labels))[:50],
        training_records=len(normalized_rows),
        testing_records=0,
        preprocessing={"header_detected": header_present, "missing_values": missing_values, "categorical_columns": categorical_columns, "duplicates_detected": duplicate_rows, "normalization": "preview only; persisted training pipeline not yet fitted"},
        preview=preview,
        is_demo_data=False,
        owner_user=user.get("username"),
    )
    await db.datasets.insert_one(record.model_dump())
    await audit(user.get("username", "unknown"), "DATASET_UPLOADED", "Dataset", record.id, f"Uploaded {filename} with {record.records} records")
    return record


@router.get("/dashboard/summary")
async def dashboard_summary(user: dict = Depends(current_user)) -> Dict[str, Any]:
    return await make_dashboard(user.get("username"))


@router.get("/url-checks", response_model=List[URLCheckRecord])
async def url_checks(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    return await list_docs(db.url_checks, 100, user.get("username"))


@router.get("/url-checks/{check_id}", response_model=URLCheckRecord)
async def url_check_detail(check_id: str, user: dict = Depends(current_user)) -> Dict[str, Any]:
    item = await db.url_checks.find_one({"$and": [{"id": check_id}, owner_filter(user.get("username"))]}, {"_id": 0})
    if not item:
        raise HTTPException(status_code=404, detail="URL check not found")
    return item


@router.post("/url-checks/analyze", response_model=URLCheckRecord)
async def analyze_url(input: URLCheckRequest, request: Request) -> URLCheckRecord:
    user = await current_user(request)
    require_writer(user)
    if not input.authorized:
        raise HTTPException(status_code=400, detail="Confirm that you own or are authorized to assess this URL")
    username = user.get("username", "unknown")
    now = time.monotonic()
    if now - url_check_rate_limit.get(username, 0) < 10:
        raise HTTPException(status_code=429, detail="Please wait 10 seconds between passive URL checks")
    url_check_rate_limit[username] = now
    try:
        result = await passive_url_analysis(input.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result = result.model_copy(update={"authorized": True})
    is_threat = result.risk_score >= 51
    action = "MONITOR_ONLY" if result.risk_score <= 25 else "ALERT_ADMIN" if result.risk_score <= 50 else "ALERT_ADMIN + SIMULATED_BLOCK_IP" if result.risk_score <= 75 else "ALERT_ADMIN + SIMULATED_BLOCK_IP + SIMULATED_ISOLATE_DEVICE"
    explanation = f"Passive URL analysis observed a risk score of {result.risk_score} from {len(result.findings)} signal(s). This is a risk indicator, not proof of compromise."
    event = SecurityEvent(source_ip="URL_ANALYZER", destination_ip=result.dns_host or "unknown", source_port=0, destination_port=443 if input.url.lower().startswith("https://") else 80, protocol="HTTPS" if input.url.lower().startswith("https://") else "HTTP", event_type="URL Risk Analysis", raw_data={"url": input.url, "authorized": True, "passive_only": True, "findings": result.findings}, processed_data={"risk_score": result.risk_score, "security_headers": result.security_headers})
    threat = await run_pipeline(event, username, {"prediction": "Potentially Risky URL" if is_threat else "Normal URL", "confidence": float(max(50, result.risk_score)), "risk_score": result.risk_score, "severity": result.severity, "is_threat": is_threat, "explanation": explanation, "action": action})
    result = result.model_copy(update={"threat_id": threat.id, "owner_user": username})
    await db.url_checks.insert_one(result.model_dump())
    await audit(username, "URL_CHECKED", "URLCheck", result.id, f"Passive authorized URL check for {result.url}")
    return result


@router.get("/dashboard/timeline")
async def dashboard_timeline(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    dashboard = await make_dashboard(user.get("username"))
    return dashboard["timeline"]


@router.get("/dashboard/threat-distribution")
async def threat_distribution(user: dict = Depends(current_user)) -> Dict[str, Any]:
    dashboard = await make_dashboard(user.get("username"))
    return {"category_distribution": dashboard["category_distribution"], "severity_distribution": dashboard["severity_distribution"]}


@router.get("/events")
async def events(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    return await list_docs(db.security_events, 100, user.get("username"))


@router.get("/events/{event_id}")
async def event_detail(event_id: str, user: dict = Depends(current_user)) -> Dict[str, Any]:
    event = await db.security_events.find_one({"$and": [{"id": event_id}, owner_filter(user.get("username"))]}, {"_id": 0})
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.post("/detection/analyze")
async def analyze(input: DetectionRequest, request: Request) -> Dict[str, Any]:
    user = await current_user(request)
    require_writer(user)
    result = classify_event(input.event_type, input.failed_attempts, input.traffic_volume)
    event = SecurityEvent(source_ip=input.source_ip, destination_ip="10.0.0.5", source_port=49200, destination_port=443, protocol="TCP", event_type=input.event_type, raw_data=input.model_dump(), processed_data={"features_extracted": True})
    threat = await run_pipeline(event, user.get("username", "ANALYST"))
    return {"prediction": result["prediction"], "is_threat": result["is_threat"], "confidence": result["confidence"], "risk_score": result["risk_score"], "severity": result["severity"], "explanation": result["explanation"], "threat_id": threat.id}


@router.get("/detections")
async def detections(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    username = user.get("username")
    threats = await list_docs(db.threat_detections, 100, username)
    for threat in threats:
        threat["event"] = await db.security_events.find_one({"$and": [{"id": threat.get("event_id")}, owner_filter(username)]}, {"_id": 0})
    return threats


@router.delete("/detections/history")
async def delete_detection_history(request: Request) -> Dict[str, Any]:
    user = await current_user(request)
    username = user.get("username")
    scope = owner_filter(username)
    threat_docs = await db.threat_detections.find(scope, {"id": 1}).to_list(10000)
    threat_ids = [item.get("id") for item in threat_docs if item.get("id")]
    results = {
        "detections": (await db.threat_detections.delete_many(scope)).deleted_count,
        "events": (await db.security_events.delete_many(scope)).deleted_count,
        "agent_executions": (await db.agent_executions.delete_many(scope)).deleted_count,
        "incidents": (await db.incidents.delete_many(scope)).deleted_count,
        "responses": (await db.response_actions.delete_many(scope)).deleted_count,
        "url_checks": (await db.url_checks.delete_many(scope)).deleted_count,
    }
    await audit(username, "DETECTION_HISTORY_DELETED", "ThreatDetection", ",".join(threat_ids[:10]) or "none", f"Deleted own detection history: {results}")
    return {"ok": True, "deleted": results}


@router.get("/detections/{detection_id}")
async def detection_detail(detection_id: str, user: dict = Depends(current_user)) -> Dict[str, Any]:
    username = user.get("username")
    threat = await db.threat_detections.find_one({"$and": [{"id": detection_id}, owner_filter(username)]}, {"_id": 0})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    threat["event"] = await db.security_events.find_one({"$and": [{"id": threat.get("event_id")}, owner_filter(username)]}, {"_id": 0})
    threat["agent_executions"] = await db.agent_executions.find({"$and": [{"event_id": threat.get("event_id")}, owner_filter(username)]}, {"_id": 0}).sort("created_at", 1).to_list(20)
    return threat


@router.get("/agents")
async def agents(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    names = ["Monitoring Agent", "Detection Agent", "Analysis Agent", "Decision Agent", "Response Agent"]
    executions = await list_docs(db.agent_executions, 2000, user.get("username"))
    counts = {name: [item for item in executions if item.get("agent_name") == name] for name in names}
    return [{"name": name, "status": "ACTIVE", "events_processed": len(counts[name]), "success_rate": 100.0 if counts[name] else 0.0, "average_response_time": round(sum(float(item.get("execution_time", 0)) for item in counts[name]) / max(1, len(counts[name])), 2), "last_activity": counts[name][0].get("created_at") if counts[name] else None, "purpose": {"Monitoring Agent": "Collects synthetic security events", "Detection Agent": "Classifies activity using the local ML baseline", "Analysis Agent": "Calculates risk from model output and context", "Decision Agent": "Applies deterministic response policy", "Response Agent": "Records SAFE_MODE simulated actions"}[name]} for name in names]


@router.get("/agents/status")
async def agent_status(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    return await agents(user)


@router.get("/agents/executions")
async def agent_executions(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    return await list_docs(db.agent_executions, 200, user.get("username"))


@router.get("/incidents")
async def incidents(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    return await list_docs(db.incidents, 100, user.get("username"))


@router.get("/incidents/{incident_id}")
async def incident_detail(incident_id: str, user: dict = Depends(current_user)) -> Dict[str, Any]:
    username = user.get("username")
    item = await db.incidents.find_one({"$and": [{"id": incident_id}, owner_filter(username)]}, {"_id": 0})
    if not item:
        raise HTTPException(status_code=404, detail="Incident not found")
    item["threat"] = await db.threat_detections.find_one({"$and": [{"id": item.get("threat_id")}, owner_filter(username)]}, {"_id": 0})
    item["responses"] = await db.response_actions.find({"$and": [{"incident_id": incident_id}, owner_filter(username)]}, {"_id": 0}).sort("created_at", 1).to_list(20)
    return item


@router.patch("/incidents/{incident_id}")
async def update_incident(incident_id: str, input: IncidentUpdate, request: Request) -> Dict[str, Any]:
    user = await current_user(request)
    if user.get("role") not in {"ADMIN", "ANALYST"}:
        raise HTTPException(status_code=403, detail="Analyst or admin role required")
    allowed = {"OPEN", "INVESTIGATING", "MITIGATED", "RESOLVED"}
    if input.status not in allowed:
        raise HTTPException(status_code=422, detail="Unsupported incident status")
    update: Dict[str, Any] = {"status": input.status}
    if input.status == "RESOLVED":
        update["resolved_at"] = datetime.now(timezone.utc)
    username = user.get("username")
    changed = await db.incidents.update_one({"$and": [{"id": incident_id}, owner_filter(username)]}, {"$set": update})
    if changed.matched_count == 0:
        raise HTTPException(status_code=404, detail="Incident not found")
    await audit(username, "INCIDENT_UPDATED", "Incident", incident_id, f"Status changed to {input.status}")
    return await db.incidents.find_one({"$and": [{"id": incident_id}, owner_filter(username)]}, {"_id": 0}) or {}


@router.get("/responses")
async def responses(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    return await list_docs(db.response_actions, 100, user.get("username"))


@router.post("/responses/simulate")
async def simulate_response(input: ResponseRequest, request: Request) -> Dict[str, Any]:
    user = await current_user(request)
    username = user.get("username")
    threat = await db.threat_detections.find_one({"$and": [{"id": input.threat_id}, owner_filter(username)]})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    response = {"id": __import__("uuid").uuid4().hex, "owner_user": username, "threat_id": input.threat_id, "action_type": input.action_type, "action_status": "COMPLETED", "reason": f"SAFE_MODE simulation: {input.action_type} would be applied; no real system was changed.", "created_at": datetime.now(timezone.utc)}
    await db.response_actions.insert_one(response)
    await audit(username, "RESPONSE_EXECUTED", "ResponseAction", response["id"], response["reason"])
    return response


@router.get("/models")
async def models(_: dict = Depends(current_user)) -> Dict[str, Any]:
    return {"production_model": "Random Forest", "models": [metric.model_dump() for metric in model_metrics()], "dataset": "Synthetic demonstration evaluation", "safe_mode": True}


@router.get("/models/metrics")
async def metrics(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    return [metric.model_dump() for metric in model_metrics()]


@router.post("/models/train")
async def train(request: Request) -> Dict[str, Any]:
    user = await current_user(request)
    if user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin role required")
    await audit(user.get("username", "admin"), "MODEL_TRAINED", "Model", "Random Forest", "Deterministic demonstration evaluation completed")
    return {"status": "completed", "metrics": [metric.model_dump() for metric in model_metrics()], "message": "Candidate evaluation completed; production model was not replaced automatically."}


@router.post("/simulator/start")
async def simulator_start(input: SimulationSettings | None = None, user: dict = Depends(current_user)) -> Dict[str, Any]:
    require_writer(user)
    username = user.get("username")
    if simulator.get("status") == "RUNNING" and simulator.get("owner_user") not in {None, username}:
        raise HTTPException(status_code=409, detail="The simulator is already owned by another active session")
    if input:
        simulator["events_per_second"] = input.events_per_second
        simulator["threat_probability"] = input.threat_probability
    return await start_simulator(username)


@router.post("/simulator/stop")
async def simulator_stop(user: dict = Depends(current_user)) -> Dict[str, Any]:
    require_writer(user)
    if simulator.get("owner_user") not in {None, user.get("username")} and user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Only the simulator owner can stop this session")
    return await stop_simulator()


@router.post("/simulator/pause")
async def simulator_pause(user: dict = Depends(current_user)) -> Dict[str, Any]:
    require_writer(user)
    if simulator.get("owner_user") not in {None, user.get("username")} and user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Only the simulator owner can pause this session")
    return await pause_simulator()


@router.post("/simulator/resume")
async def simulator_resume(user: dict = Depends(current_user)) -> Dict[str, Any]:
    require_writer(user)
    if simulator.get("owner_user") not in {None, user.get("username")} and user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Only the simulator owner can resume this session")
    return await start_simulator(user.get("username"))


@router.get("/simulator/status")
async def simulator_status(_: dict = Depends(current_user)) -> Dict[str, Any]:
    status = simulator.copy()
    status.pop("owner_user", None)
    return status


@router.get("/analytics/overview")
async def analytics(user: dict = Depends(current_user)) -> Dict[str, Any]:
    username = user.get("username")
    dashboard = await make_dashboard(username)
    threats = await list_docs(db.threat_detections, 1000, username)
    return {"summary": dashboard, "confidence": [{"bucket": bucket, "count": sum(1 for item in threats if bucket[0] <= float(item.get("confidence", 0)) < bucket[1])} for bucket in [(0, 60), (60, 75), (75, 90), (90, 101)]], "source_ips": [{"source": source, "count": count} for source, count in Counter(item.get("source_ip", "unknown") for item in [await db.security_events.find_one({"$and": [{"id": threat.get("event_id")}, owner_filter(username)]}) for threat in threats] if item).most_common(6)]}


@router.get("/reports/summary")
async def report_summary(user: dict = Depends(current_user)) -> Dict[str, Any]:
    dashboard = await make_dashboard(user.get("username"))
    return {"generated_at": datetime.now(timezone.utc), "title": "CyberGuard AI Security Operations Report", "executive_summary": "This report summarizes SAFE_MODE simulated security activity processed by the local deterministic detection and agent workflow.", "statistics": dashboard, "attack_categories": dashboard["category_distribution"], "severity_distribution": dashboard["severity_distribution"], "agent_performance": await agents(user)}


@router.get("/reports/export.csv")
async def export_csv(user: dict = Depends(current_user)) -> Response:
    threats = await list_docs(db.threat_detections, 1000, user.get("username"))
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Threat ID", "Timestamp", "Prediction", "Confidence", "Risk Score", "Severity", "Status", "Action"])
    for threat in threats:
        writer.writerow([threat.get("id"), threat.get("timestamp"), threat.get("prediction"), threat.get("confidence"), threat.get("risk_score"), threat.get("severity"), threat.get("status"), threat.get("action")])
    return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=cyberguard-threat-report.csv"})


@router.get("/reports/export.pdf")
async def export_pdf(user: dict = Depends(current_user)) -> Response:
    dashboard = await make_dashboard(user.get("username"))
    lines = ["CYBERGUARD AI - SECURITY OPERATIONS REPORT", "SAFE_MODE: ENABLED", "", "EXECUTIVE SUMMARY", "Simulated security events were classified by a deterministic local model and processed through five agents.", "", f"Total events: {dashboard['total_events']}", f"Threats detected: {dashboard['threats_detected']}", f"Active incidents: {dashboard['active_incidents']}", f"Simulated responses: {dashboard['simulated_responses']}"]
    body = "BT /F1 11 Tf 50 760 Td " + " ".join(f"({line.replace('(', '[').replace(')', ']')}) Tj 0 -16 Td" for line in lines) + " ET"
    pdf = f"%PDF-1.4\n1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources<< /Font<< /F1 4 0 R >> >> /Contents 5 0 R >>endobj\n4 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n5 0 obj<< /Length {len(body)} >>stream\n{body}\nendstream endobj\nxref\n0 6\n0000000000 65535 f \ntrailer<< /Root 1 0 R /Size 6 >>\nstartxref\n0\n%%EOF"
    return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=cyberguard-security-report.pdf"})


@router.get("/audit-logs")
async def audit_logs(user: dict = Depends(current_user)) -> List[Dict[str, Any]]:
    return await list_docs(db.audit_logs, 500, user.get("username"))


@router.get("/settings")
async def settings(_: dict = Depends(current_user)) -> Dict[str, Any]:
    return {"safe_mode": True, "automatic_simulated_response": True, "real_time_monitoring": True, "detection_threshold": 0.75, "risk_scoring": "Configurable project mechanism; not an industry-standard score"}


@router.patch("/settings")
async def update_setting(input: SettingUpdate, request: Request) -> Dict[str, Any]:
    user = await current_user(request)
    if user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin role required")
    await db.system_settings.update_one({"key": input.key}, {"$set": {"key": input.key, "value": input.value}}, upsert=True)
    await audit(user.get("username", "admin"), "SETTINGS_CHANGED", "SystemSetting", input.key, f"Setting changed to {input.value}")
    return {"key": input.key, "value": input.value}


@router.websocket("/ws/security-events")
async def websocket_events(websocket: WebSocket) -> None:
    try:
        payload = await websocket_user(websocket)
    except HTTPException:
        await websocket.close(code=4401)
        return
    await manager.connect(websocket, payload.get("username", "unknown"))
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
