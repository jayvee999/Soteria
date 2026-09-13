"""Soteria data models - pure Python dataclasses."""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Role(str, Enum):
    ADMIN = "admin"
    HUNTER = "hunter"


class BlockType(str, Enum):
    CLOUDFLARE = "cloudflare"
    WAF = "waf"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    JS_CHALLENGE = "js_challenge"
    UNKNOWN = "unknown"


@dataclass
class ReconResult:
    target_domain: str
    url: str
    status_code: Optional[int] = None
    technologies: List[str] = field(default_factory=list)
    title: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    content_length: Optional[int] = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    behind_cdn: bool = False
    id: Optional[int] = None


@dataclass
class Finding:
    url: str
    type: str
    severity: Severity
    title: str
    description: str
    finding_id: str = field(default_factory=lambda: f"F-{uuid.uuid4().hex[:8].upper()}")
    raw_request: Optional[str] = None
    raw_response: Optional[str] = None
    curl_command: Optional[str] = None
    reproduction_steps: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    remediation: Optional[str] = None
    verified: bool = False
    false_positive: bool = False
    reported: bool = False
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ai_notes: Optional[str] = None


@dataclass
class User:
    username: str
    password_hash: str
    role: Role = Role.HUNTER
    id: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None
    password_changed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    locked_until: Optional[datetime] = None
    active: bool = True


@dataclass
class LoginAttempt:
    username: str
    success: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: Optional[int] = None
    ip_hint: Optional[str] = None


@dataclass
class Session:
    token: str
    username: str
    role: Role
    created_at: datetime
    expires_at: datetime


@dataclass
class TrainingEntry:
    instruction: str
    input: str
    output: str
    category: Optional[str] = None
    source: Optional[str] = None
    id: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AIResponse:
    content: str
    model: str
    provider: str
    tokens_used: Optional[int] = None
    latency_ms: Optional[float] = None


@dataclass
class BlockDetection:
    block_type: BlockType = BlockType.UNKNOWN
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    suggested_bypass: Optional[str] = None
