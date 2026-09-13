import json
import logging
import subprocess
from .. import database as db
from ..models import ReconResult

log = logging.getLogger(__name__)


class ReconEngine:
    MAX_SUBS = 200  # Hard cap to prevent hangs

    def __init__(self):
        self.subs = set()
        self.live = []

    def run(self, domain: str):
        log.info("Enumerating subdomains for %s", domain)
        subs = self.get_subs(domain)
        log.info("Found %d unique subdomains", len(subs))
        if not subs:
            log.warning("No subdomains found for %s", domain)
            return []
        subs = subs[:self.MAX_SUBS]
        log.info("Checking up to %d live hosts", len(subs))
        live = self.check_live(subs)
        log.info("%d live hosts", len(live))
        return live

    def get_subs(self, domain: str):
        # crt.sh (with size limit and timeout)
        try:
            r = subprocess.run(
                ["curl", "-s", "-m", "15", "--max-filesize", "5000000",
                 f"https://crt.sh/?q=%25.{domain}&output=json"],
                capture_output=True, text=True, timeout=20
            )
            if r.stdout and r.stdout.strip().startswith("["):
                data = json.loads(r.stdout)
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().replace("*.", "").replace("www.", "")
                        if name and domain in name and "@" not in name:
                            self.subs.add(name)
        except Exception as e:
            log.warning("crt.sh failed: %s", e)

        # subfinder (optional)
        try:
            r = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n"):
                    if line.strip() and domain in line:
                        self.subs.add(line.strip().lower())
        except Exception:
            log.debug("subfinder not available")

        # assetfinder (optional)
        try:
            r = subprocess.run(
                ["assetfinder", "--subs-only", domain],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0:
                for line in r.stdout.strip().split("\n"):
                    if line.strip() and domain in line:
                        self.subs.add(line.strip().lower())
        except Exception:
            log.debug("assetfinder not available")

        if not self.subs:
            self.subs.add(domain)

        return sorted(self.subs)

    def check_live(self, subdomains: list):
        for sub in subdomains:
            for scheme in ["https://", "http://"]:
                try:
                    r = subprocess.run(
                        ["curl", "-s", "-m", "5", "-o", "/dev/null",
                         "-w", "%{http_code}", "-L", f"{scheme}{sub}"],
                        capture_output=True, text=True, timeout=8
                    )
                    code = r.stdout.strip()
                    if code and code != "000":
                        result = ReconResult(
                            target_domain=sub,
                            url=f"{scheme}{sub}",
                            status_code=int(code) if code.isdigit() else 0,
                            behind_cdn=False
                        )
                        self.live.append(result)
                        db.recon_save(result)
                        print(f"  [+] {scheme}{sub} [{code}]")
                        break
                except Exception:
                    pass
        return self.live
