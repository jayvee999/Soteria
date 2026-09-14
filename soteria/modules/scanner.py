import json
import logging
import subprocess
from .. import database as db
from ..models import Finding, Severity
from .authorization.hunt import HuntManager, HuntError

log = logging.getLogger(__name__)


class VulnerabilityScanner:
    REAL_EXPOSURE_CODES = ["200", "201", "202"]

    def __init__(self, hunt_id: str = None):
        self.hunt_id = hunt_id
        self.hunt = HuntManager(db=db._connect())

    def run(self, target: str, templates=None, severity=None, target_context=None):
        # LEGAL GATE: require valid hunt ID
        if not self.hunt_id:
            raise HuntError(
                "Scan requires a hunt ID. Use --hunt HUNT-XXXX or create one with "
                "'soteria hunt create'."
            )

        # Verify hunt is valid and target is in scope
        self.hunt.require_hunt(self.hunt_id, target)
        log.info("Authorized scan for %s (hunt=%s)", target, self.hunt_id)

        # Enforce plan limits
        try:
            from .billing.enforcer import PlanEnforcer, PlanLimitError
            conn = db._connect()
            hunt_row = conn.execute(
                "SELECT org_id FROM hunts WHERE hunt_id = ?", (self.hunt_id,)
            ).fetchone()
            if hunt_row:
                enforcer = PlanEnforcer(db=conn)
                enforcer.check_scan_allowed(hunt_row["org_id"], target)
        except Exception as e:
            # If enforcer module doesn't exist yet, log and continue
            log.debug("Plan enforcement skipped: %s", e)

        # Log the authorized scan
        db.log_action(
            "authorized_scan",
            target=target,
            tool="scanner",
            output_summary=f"hunt_id={self.hunt_id}",
            status="ok",
        )

        # Nuclei scan (optional)
        try:
            args = ["-u", target, "-silent", "-json"]
            r = subprocess.run(["nuclei"] + args, capture_output=True, text=True, timeout=300)
            if r.stdout:
                self._parse_nuclei_output(target, r.stdout)
        except FileNotFoundError:
            pass
        except Exception as e:
            log.warning("nuclei failed: %s", e)

        # Custom checks
        self._custom_checks(target)

    def _parse_nuclei_output(self, target, output):
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                finding = Finding(
                    url=data.get("matched-at", target),
                    type=info.get("name", "nuclei-finding"),
                    severity=Severity(info.get("severity", "medium").upper()),
                    title=info.get("name", "Nuclei Finding"),
                    description=info.get("description", ""),
                    curl_command=f"curl -s {data.get('matched-at', target)}",
                    remediation=info.get("remediation", ""),
                )
                db.finding_save(finding)
                self._compliance_tag(finding)
            except Exception as e:
                log.debug("Parse error: %s", e)

    def _custom_checks(self, target):
        checks = {
            "/.git/config": ("git_exposure", Severity.HIGH),
            "/.env": ("env_exposure", Severity.CRITICAL),
            "/.env.local": ("env_exposure", Severity.CRITICAL),
            "/.git/HEAD": ("git_exposure", Severity.HIGH),
            "/backup.zip": ("backup_exposure", Severity.HIGH),
            "/backup.sql": ("backup_exposure", Severity.HIGH),
            "/phpinfo.php": ("debug_exposure", Severity.MEDIUM),
            "/actuator/env": ("spring_actuator", Severity.HIGH),
        }
        base = target.rstrip('/')
        for path, (f_type, severity) in checks.items():
            try:
                r = subprocess.run(
                    ["curl", "-s", "-m", "6", "-o", "/dev/null",
                     "-w", "%{http_code}", "-L", f"{base}{path}"],
                    capture_output=True, text=True, timeout=10
                )
                code = r.stdout.strip()
                if code in self.REAL_EXPOSURE_CODES:
                    finding = Finding(
                        url=f"{base}{path}",
                        type=f_type,
                        severity=severity,
                        title=f"Exposed: {path}",
                        description=f"Endpoint {path} returned HTTP {code}.",
                        curl_command=f"curl -s -L {base}{path}",
                    )
                    db.finding_save(finding)
                    self._compliance_tag(finding)
                    print(f"  [!!!] {severity.value}: {path} [{code}]")
            except Exception:
                pass

    def _compliance_tag(self, finding):
        """Auto-tag finding with compliance controls."""
        try:
            from .compliance.tagger import tag_finding
            tag_finding(db._connect(), finding.finding_id, finding.type)
        except Exception as e:
            log.debug("Compliance tag failed: %s", e)
