import time, threading, sys
from datetime import datetime
from pathlib import Path
from .database import finding_list


class LiveDashboard:
    def __init__(self, soteria_dir: Path):
        self.soteria_dir = soteria_dir
        self.running = False
        self.paused = False
        self.start_time = None
        self.targets_completed = 0
        self.total_targets = 0
        self.current_target = ""
        self.current_phase = ""
        self.lock = threading.Lock()
        self.critical = 0
        self.high = 0
        self.medium = 0
        self.low = 0
        self.scan_frames = ["☽", "✚", "☾"]
        self.frame_idx = 0
        self.dots = ["", ".", "..", "..."]
        self.dot_idx = 0

    def start(self, total_targets: int):
        self.running = True
        self.start_time = datetime.now()
        self.total_targets = total_targets
        self._animation_loop()
        self._render_loop()

    def stop(self):
        self.running = False

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def update(self, target: str = "", phase: str = "", completed: bool = False):
        with self.lock:
            if target:
                self.current_target = target
            if phase:
                self.current_phase = phase
            if completed:
                self.targets_completed += 1

    def add_finding(self, severity: str):
        if severity == "Critical":
            self.critical += 1
        elif severity == "High":
            self.high += 1
        elif severity == "Medium":
            self.medium += 1
        else:
            self.low += 1

    def _animation_loop(self):
        def loop():
            while self.running:
                self.frame_idx = (self.frame_idx + 1) % 3
                self.dot_idx = (self.dot_idx + 1) % 4
                time.sleep(0.4)
        threading.Thread(target=loop, daemon=True).start()

    def _render_loop(self):
        def loop():
            while self.running:
                if not self.paused:
                    self._render()
                time.sleep(2)
        threading.Thread(target=loop, daemon=True).start()

    def _render(self):
        sys.stdout.write("\033[2J\033[H")

        elapsed = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        elapsed_str = f"{int(elapsed // 60)}m {int(elapsed % 60)}s"

        scan_icon = self.scan_frames[self.frame_idx]
        dots = self.dots[self.dot_idx]

        if self.total_targets > 0:
            pct = int((self.targets_completed / self.total_targets) * 100)
            filled = int(pct / 5)
            bar = "█" * filled + "░" * (20 - filled)
        else:
            pct = 0
            bar = "░" * 20

        if self.paused:
            status = "\033[93m⏸  PAUSED\033[0m"
        else:
            status = f"\033[92m{scan_icon}  HUNTING{dots}\033[0m"

        findings = finding_list(exclude_fp=True)
        verified = finding_list(verified_only=True)

        print(f"""
╔══════════════════════════════════════════════════════════════════╗
║                    KERES LIVE DASHBOARD                         ║
╠══════════════════════════════════════════════════════════════════╣
║  ⏱️  Elapsed: {elapsed_str:<48} ║
║  📡 Status:  {status:<48} ║
║  🎯 Progress: [{bar}] {pct}%                          ║
║  📍 Current:  {self.current_target or 'Waiting...':<48} ║
║  ⚙️  Phase:    {self.current_phase or 'Initializing...':<48} ║
╠══════════════════════════════════════════════════════════════════╣
║  📊 FINDINGS                                                   ║
║     🔴 Critical: {self.critical:<3}  🟠 High: {self.high:<3}  🟡 Medium: {self.medium:<3}  🟢 Low: {self.low:<3}              ║
║     ✅ Verified: {len(verified):<3}  📝 Total: {len(findings):<3}                                         ║
╠══════════════════════════════════════════════════════════════════╣
║  📋 LATEST FINDINGS                                            ║
""")

        for f in findings[:5]:
            sev_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "⚪"}.get(f.severity.value, "⚪")
            verified_mark = "✅" if f.verified else "⏳"
            title = f.title[:52] + "..." if len(f.title) > 52 else f.title
            print(f"║  {sev_emoji} {verified_mark} {title:<52} ║")

        for _ in range(5 - len(findings[:5])):
            print(f"║  {'':<57} ║")

        print(f"""╠══════════════════════════════════════════════════════════════════╣
║  ⌨️  [p]ause  [r]esume  [s]top  [v]iew findings  [q]uit        ║
╚══════════════════════════════════════════════════════════════════╝
""")
