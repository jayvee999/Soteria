from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class Role(str, Enum):
    ADMIN = "admin"
    HUNTER = "hunter"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"

class BlockType(str, Enum):
    CLOUDFLARE = "cloudflare"
    WAF = "waf"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    JS_CHALLENGE = "js_challenge"
    UNKNOWN = "unknown"

class ReconResult(BaseModel):
    id: Optional[int] = None
    target_domain: str
    url: str
    status_code: Optional[int] = None
    technologies: List[str] = Field(default_factory=list)
    title: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    content_length: Optional[int] = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    behind_cdn: bool = False

class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"F-{uuid.uuid4().hex[:8].upper()}")
    url: str
    type: str
    severity: Severity
    title: str
    description: str
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    curl_command: Optional[str] = None
    reproduction_steps: List[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    remediation: Optional[str] = None
    verified: bool = False
    false_positive: bool = False
    reported: bool = False
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ai_notes: Optional[str] = None

class ScanLogEntry(BaseModel):
    id: Optional[int] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    action: str
    target: Optional[str] = None
    tool: Optional[str] = None
    command: Optional[str] = None
    output_summary: Optional[str] = None
    status: str = "ok"
    operator: Optional[str] = None

class User(BaseModel):
    id: Optional[int] = None
    username: str
    password_hash: str
    role: Role = Role.HUNTER
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None
    password_changed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    locked_until: Optional[datetime] = None
    active: bool = True

class LoginAttempt(BaseModel):
    id: Optional[int] = None
    username: str
    success: bool
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ip_hint: Optional[str] = None

class Session(BaseModel):
    token: str
    username: str
    role: Role
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime

class LicenseRecord(BaseModel):
    license_id: str
    key_hash: str
    role: Role
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    note: Optional[str] = None

class LicenseActivation(BaseModel):
    id: Optional[int] = None
    license_id: str
    machine_fingerprint: str
    activated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    active: bool = True

class AIResponse(BaseModel):
    content: str
    model: str
    provider: str
    tokens_used: Optional[int] = None
    latency_ms: Optional[float] = None

class BlockDetection(BaseModel):
    block_type: BlockType = BlockType.UNKNOWN
    confidence: float = 0.0
    evidence: List[str] = Field(default_factory=list)
    suggested_bypass: Optional[str] = None

class TrainingEntry(BaseModel):
    id: Optional[int] = None
    instruction: str
    input: str
    output: str
    category: Optional[str] = None
    source: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
