from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UserCreate(BaseModel):
    username: str
    password: str = Field(min_length=6)
    role: str = "VIEWER"


class LoginRequest(BaseModel):
    username: str
    password: str


class UserPublic(BaseModel):
    id: str
    username: str
    role: str


class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    event_type: str
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    processed_data: Dict[str, Any] = Field(default_factory=dict)
    status: str = "PROCESSED"
    owner_user: Optional[str] = None


class ThreatDetection(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    prediction: str
    confidence: float
    risk_score: int
    severity: str
    is_threat: bool
    explanation: str
    model_name: str = "Deterministic Random Forest Baseline"
    status: str = "OPEN"
    action: str = "MONITOR_ONLY"
    owner_user: Optional[str] = None


class AgentExecution(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    event_id: str
    agent_name: str
    input_data: Dict[str, Any] = Field(default_factory=dict)
    output_data: Dict[str, Any] = Field(default_factory=dict)
    status: str = "COMPLETED"
    execution_time: float = 0.0
    created_at: datetime = Field(default_factory=utc_now)
    owner_user: Optional[str] = None


class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    threat_id: str
    title: str
    description: str
    severity: str
    status: str = "OPEN"
    source_ip: str
    assigned_to: str = "Admin"
    created_at: datetime = Field(default_factory=utc_now)
    resolved_at: Optional[datetime] = None
    owner_user: Optional[str] = None


class ResponseAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    incident_id: Optional[str] = None
    threat_id: str
    action_type: str
    action_status: str = "COMPLETED"
    reason: str
    created_at: datetime = Field(default_factory=utc_now)
    owner_user: Optional[str] = None


class AuditLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    user: str
    action: str
    entity: str
    entity_id: str = "system"
    details: str
    timestamp: datetime = Field(default_factory=utc_now)
    owner_user: Optional[str] = None


class IncidentUpdate(BaseModel):
    status: str


class SimulationSettings(BaseModel):
    events_per_second: float = Field(default=0.7, ge=0.1, le=5)
    threat_probability: float = Field(default=0.48, ge=0, le=1)


class ResponseRequest(BaseModel):
    threat_id: str
    action_type: str


class SettingUpdate(BaseModel):
    key: str
    value: Any


class DetectionRequest(BaseModel):
    event_type: str
    source_ip: str = "192.168.1.25"
    failed_attempts: int = 0
    traffic_volume: int = 120


class ModelMetric(BaseModel):
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    roc_auc: float
    training_time_ms: float
    prediction_time_ms: float
    evaluated_records: int
    dataset_label: str = "Synthetic demonstration evaluation"


class ReportResponse(BaseModel):
    generated_at: datetime
    title: str
    executive_summary: str
    statistics: Dict[str, Any]
    attack_categories: List[Dict[str, Any]]
    severity_distribution: List[Dict[str, Any]]
    agent_performance: List[Dict[str, Any]]


class DatasetRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    filename: str
    format: str
    records: int
    features: int
    classes: List[str]
    training_records: int
    testing_records: int
    preprocessing: Dict[str, Any] = Field(default_factory=dict)
    preview: List[Dict[str, Any]] = Field(default_factory=list)
    is_demo_data: bool = False
    uploaded_at: datetime = Field(default_factory=utc_now)
    owner_user: Optional[str] = None


class URLCheckRequest(BaseModel):
    url: str
    authorized: bool = False


class URLCheckRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    url: str
    final_url: Optional[str] = None
    authorized: bool = False
    reachable: bool = False
    status_code: Optional[int] = None
    redirects: int = 0
    risk_score: int = 0
    severity: str = "LOW"
    classification: str = "NO HIGH-RISK SIGNAL"
    title: Optional[str] = None
    findings: List[str] = Field(default_factory=list)
    security_headers: Dict[str, bool] = Field(default_factory=dict)
    dns_host: Optional[str] = None
    tls_valid: Optional[bool] = None
    error: Optional[str] = None
    threat_id: Optional[str] = None
    checked_at: datetime = Field(default_factory=utc_now)
    owner_user: Optional[str] = None
