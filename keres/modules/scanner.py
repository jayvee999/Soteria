import json, logging, subprocess
from .. import database as db
from ..models import Finding, Severity

log = logging.getLogger(__name__)


class VulnerabilityScanner:
    def __init__(self):
        pass

    def run(self, target: str, templates: list = None, severity: str = None, target_context: str = None):
        log.info("Scanning %s", target)

        # Nuclei scan
        try:
            args = ["-u", target, "-silent", "-json"]
            if templates:
                for t in templates:
                    args += ["-t", t]
            if severity:
                args += ["-severity", severity]
            r = subprocess.run(
                ["nuclei"] + args,
                capture_output=True, text=True, timeout=300
            )
            if r.stdout:
                self._parse_nuclei_output(target, r.stdout)
        except Exception as e:
            log.warning("nuclei failed: %s", e)

        # Custom checks
        self._custom_checks(target)

    def _parse_nuclei_output(self, target: str, output: str):
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
                log.info("Found: %s", finding.title)
            except Exception as e:
                log.debug("Parse error: %s", e)

    def _custom_checks(self, target: str):
        paths = [
            "/.git/config", "/.env", "/robots.txt", "/sitemap.xml",
            "/wp-admin", "/wp-json/wp/v2/users", "/admin", "/debug",
            "/phpinfo.php", "/.well-known/security.txt"
        ]
        for path in paths:
            try:
                r = subprocess.run(
                    ["curl", "-s", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", f"{target.rstrip('/')}{path}"],
                    capture_output=True, text=True, timeout=8
                )
                code = r.stdout.strip()
                if code and code not in ["000", "404"]:
                    finding = Finding(
                        url=f"{target.rstrip('/')}{path}",
                        type="information_disclosure",
                        severity=Severity.MEDIUM if code == "200" else Severity.LOW,
                        title=f"Exposed: {path}",
                        description=f"Endpoint {path} returned HTTP {code}",
                        curl_command=f"curl -s {target.rstrip('/')}{path}",
                    )
                    db.finding_save(finding)
            except Exception:
                pass
