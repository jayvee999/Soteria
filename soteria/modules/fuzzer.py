import logging, subprocess, threading, re
from .. import database as db
from ..models import Finding, Severity

log = logging.getLogger(__name__)


class CustomFuzzer:
    def run(self, url: str, params: list = None):
        log.info("Fuzzing %s", url)
        if params:
            for param in params:
                self.fuzz_sqli(url, param)
                self.fuzz_xss(url, param)
                self.fuzz_ssrf(url, param)
        self.fuzz_idor(url)
        self.fuzz_race(url)

    def fuzz_sqli(self, url: str, param: str):
        payloads = ["'", '"', "1' OR '1'='1"]
        for payload in payloads:
            test_url = url.replace(f"{param}=", f"{param}={payload}")
            try:
                r = subprocess.run(["curl", "-s", "-m", "10", test_url], capture_output=True, text=True, timeout=12)
                if any(err in r.stdout.lower() for err in ["sql", "mysql", "postgresql", "syntax error"]):
                    finding = Finding(
                        url=test_url, type="sqli", severity=Severity.CRITICAL,
                        title="Potential SQL Injection",
                        description=f"SQL error with payload: {payload}",
                        curl_command=f"curl -s '{test_url}'"
                    )
                    db.finding_save(finding)
            except Exception:
                pass

    def fuzz_xss(self, url: str, param: str):
        payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for payload in payloads:
            test_url = url.replace(f"{param}=", f"{param}={payload}")
            try:
                r = subprocess.run(["curl", "-s", "-m", "5", test_url], capture_output=True, text=True, timeout=8)
                if payload in r.stdout:
                    finding = Finding(
                        url=test_url, type="xss", severity=Severity.HIGH,
                        title="Potential XSS",
                        description="Payload reflected in response",
                        curl_command=f"curl -s '{test_url}'"
                    )
                    db.finding_save(finding)
            except Exception:
                pass

    def fuzz_idor(self, url: str):
        ids = re.findall(r'/(\d+)', url)
        for id_val in ids[:3]:
            for test_id in [int(id_val)+1, int(id_val)-1, 0, 1]:
                test_url = url.replace(f"/{id_val}", f"/{test_id}")
                try:
                    r = subprocess.run(["curl", "-s", "-m", "5", test_url], capture_output=True, text=True, timeout=8)
                    if r.stdout and len(r.stdout) > 100:
                        finding = Finding(
                            url=test_url, type="idor", severity=Severity.HIGH,
                            title="Potential IDOR",
                            description=f"Different response for ID {test_id}",
                            curl_command=f"curl -s '{test_url}'"
                        )
                        db.finding_save(finding)
                        break
                except Exception:
                    pass

    def fuzz_ssrf(self, url: str, param: str):
        payloads = ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080"]
        for payload in payloads:
            test_url = url.replace(f"{param}=", f"{param}={payload}")
            try:
                r = subprocess.run(["curl", "-s", "-m", "10", test_url], capture_output=True, text=True, timeout=12)
                if "ami-id" in r.stdout or "instance-id" in r.stdout:
                    finding = Finding(
                        url=test_url, type="ssrf", severity=Severity.CRITICAL,
                        title="SSRF to AWS Metadata",
                        description="Successfully accessed cloud metadata endpoint",
                        curl_command=f"curl -s '{test_url}'"
                    )
                    db.finding_save(finding)
            except Exception:
                pass

    def fuzz_race(self, url: str):
        results = []
        def send():
            try:
                r = subprocess.run(["curl", "-s", "-m", "5", "-X", "POST", url], capture_output=True, text=True, timeout=8)
                results.append(r.returncode)
            except Exception:
                pass
        threads = [threading.Thread(target=send) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if len(set(results)) > 1:
            finding = Finding(
                url=url, type="race_condition", severity=Severity.MEDIUM,
                title="Potential Race Condition",
                description=f"Different responses from concurrent requests: {results}",
                curl_command=f"# 5 simultaneous POST requests to {url}"
            )
            db.finding_save(finding)
