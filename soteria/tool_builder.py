import logging, re
from typing import Dict, List, Optional, Tuple
import httpx
from . import database as db, rate_limiter
from .config import Config
from .models import BlockDetection, BlockType
from .subprocess_runner import RunResult

log = logging.getLogger(__name__)

_CF_PATTERNS = [r"cloudflare", r"cf-ray:", r"attention required"]
_WAF_PATTERNS = [r"web application firewall", r"access denied", r"403 forbidden", r"mod_security", r"request blocked"]
_JS_PATTERNS = [r"checking your browser", r"enable javascript", r"just a moment"]
_RATE_PATTERNS = [r"rate limit", r"too many requests", r"slow down", r"429"]


def detect_block(response=None, run_result=None, status_code=None):
    evidence = []
    scores = {}
    body = ""
    code = status_code or 0

    if response:
        code = response.status_code
        body = response.text.lower()[:4096]
    if run_result:
        body += (run_result.stdout + run_result.stderr).lower()

    if code == 429 or any(re.search(p, body) for p in _RATE_PATTERNS):
        evidence.append("rate-limit")
        scores[BlockType.RATE_LIMIT] = 0.95

    cf = sum(1 for p in _CF_PATTERNS if re.search(p, body))
    if cf >= 2:
        evidence.append(f"cloudflare ({cf})")
        scores[BlockType.CLOUDFLARE] = min(0.5 + cf * 0.15, 0.99)

    js = sum(1 for p in _JS_PATTERNS if re.search(p, body))
    if js >= 1:
        evidence.append(f"js challenge ({js})")
        scores[BlockType.JS_CHALLENGE] = min(0.6 + js * 0.15, 0.99)

    waf = sum(1 for p in _WAF_PATTERNS if re.search(p, body))
    if code == 403 or waf >= 1:
        evidence.append(f"waf ({waf})")
        scores[BlockType.WAF] = min(0.4 + waf * 0.15, 0.95)

    if not scores:
        return BlockDetection(block_type=BlockType.UNKNOWN, confidence=0.0, evidence=["none"])

    best = max(scores, key=scores.get)
    return BlockDetection(block_type=best, confidence=scores[best], evidence=evidence)


_BYPASS = {
    BlockType.CLOUDFLARE: [
        {"name": "origin_ip", "desc": "Resolve origin IP", "action": "resolve_origin"},
        {"name": "mobile_api", "desc": "Try mobile API", "action": "try_alternative"}
    ],
    BlockType.RATE_LIMIT: [
        {"name": "add_delays", "desc": "Reduce rate", "action": "throttle"}
    ],
    BlockType.WAF: [
        {"name": "encode", "desc": "Encode payloads", "action": "encode"}
    ],
    BlockType.JS_CHALLENGE: [
        {"name": "browser", "desc": "Manual browser", "action": "flag_manual"}
    ],
    BlockType.TIMEOUT: [
        {"name": "reduce_threads", "desc": "Reduce threads", "action": "reduce"}
    ],
}


def get_bypass_strategies(block: BlockDetection):
    return _BYPASS.get(block.block_type, [])


class AdaptationEngine:
    def __init__(self, cfg: Config, ai=None, operator=None):
        self._cfg = cfg
        self._ai = ai
        self._operator = operator

    def handle_block(self, tool, target, orig_cmd, response=None, run_result=None):
        detection = detect_block(response, run_result)
        strategies = get_bypass_strategies(detection)
        suggestions = [s["desc"] for s in strategies]

        db.log_action("block_detected", target=target, tool=tool,
                      output_summary=f"type={detection.block_type.value} conf={detection.confidence:.2f}",
                      status="blocked", operator=self._operator)

        if self._ai and detection.block_type != BlockType.UNKNOWN:
            try:
                ai_r = self._ai.adapt_blocked_tool(tool, detection.block_type.value, orig_cmd, target)
                if ai_r:
                    suggestions.append(f"[AI] {ai_r.content}")
            except Exception:
                pass

        for s in strategies:
            if s.get("action") == "throttle":
                rate_limiter.throttle(target)

        return detection, suggestions
