from pathlib import Path
from .config import load as load_config
from .database import init as init_db, finding_list
from .modules.recon import ReconEngine
from .modules.scanner import VulnerabilityScanner
from .modules.fuzzer import CustomFuzzer
from .modules.report import ReportGenerator
from .dashboard import LiveDashboard


def interactive_hunt():
    keres_dir = Path.home() / ".keres"
    cfg = load_config(keres_dir / "config.yaml")
    init_db(keres_dir / "keres.db")

    print("""
╔══════════════════════════════════════════════════╗
║              ☽ ✚ ☾  KERES HUNT                  ║
║         Interactive Hunting Session              ║
╚══════════════════════════════════════════════════╝
""")

    programs = list(cfg.raw().get("programs", {}).keys())
    if not programs:
        print("[!] No programs configured. Edit ~/.keres/config.yaml")
        return

    for i, prog in enumerate(programs, 1):
        pdata = cfg.raw()["programs"][prog]
        out_domains = pdata.get("out_of_scope", {}).get("domains", [])
        rate = pdata.get("rate_limit", "?")
        print(f"  [{i}] {prog}")
        if out_domains:
            print(f"      Excluded: {', '.join(out_domains)}")
        print(f"      Rate limit: {rate} req/s")

    choice = input("\n🔢 Select program: ").strip()
    try:
        idx = int(choice) - 1
        program_name = programs[idx]
    except (ValueError, IndexError):
        program_name = choice if choice in programs else programs[0]
    print(f"[+] Selected: {program_name}")

    scope = cfg.raw()["programs"][program_name]
    out_of_scope = scope.get("out_of_scope", {}).get("domains", [])
    if out_of_scope:
        print("\n🛡️  OUT OF SCOPE:")
        for d in out_of_scope:
            print(f"   ❌ {d}")
        print("   Everything else is fair game.\n")

    print("🎯 TARGETS (empty = use program name as target)")
    targets = []
    while True:
        t = input("   > ").strip()
        if not t:
            break
        targets.append(t)

    if not targets:
        targets = [program_name]
        print(f"[*] No targets given. Will scan: {targets[0]}")

    print(f"[+] {len(targets)} target(s)")

    print("\n📝 ADDITIONAL CONTEXT (optional, helps AI)")
    print("   Examples: tech stack, auth method, known protections")
    context_lines = []
    while True:
        line = input("   > ").strip()
        if not line:
            break
        context_lines.append(line)
    target_context = "\n".join(context_lines) if context_lines else None

    print("""
⚙️  PHASES:
   [1] Full Hunt (Recon → Scan → Fuzz → Report)
   [2] Quick Hunt (Recon → Scan → Report)
   [3] Recon Only
   [4] Scan Only
   [5] Recon + Scan (no report)
""")
    phase_choice = input("🔢 Select phase [1]: ").strip() or "1"
    do_recon = phase_choice in ["1", "2", "3", "5"]
    do_scan = phase_choice in ["1", "2", "4", "5"]
    do_fuzz = phase_choice == "1"
    do_report = phase_choice in ["1", "2"]

    print(f"""
╔══════════════════════════════════════════════════╗
║                 HUNT SUMMARY                     ║
║  Program:    {program_name:<35} ║
║  Targets:    {len(targets):<35} ║
║  Recon:      {'✅' if do_recon else '❌':<35} ║
║  Scan:       {'✅' if do_scan else '❌':<35} ║
║  Fuzz:       {'✅' if do_fuzz else '❌':<35} ║
║  Report:     {'✅' if do_report else '❌':<35} ║
║  Context:    {'✅' if target_context else '❌':<35} ║
╚══════════════════════════════════════════════════╝
""")
    if input("🚀 Launch hunt? [Y/n]: ").strip().lower() == "n":
        return

    dashboard = LiveDashboard(keres_dir)
    dashboard.start(len(targets))

    for target in targets:
        dashboard.update(target=target, phase="Reconnaissance")
        if do_recon:
            ReconEngine().run(target)
        if do_scan:
            dashboard.update(phase="Vulnerability Scanning")
            VulnerabilityScanner().run(target, target_context=target_context)
        if do_fuzz:
            dashboard.update(phase="Fuzzing")
            CustomFuzzer().run(target)
        if do_report:
            dashboard.update(phase="Generating Report")
            ReportGenerator().run(program_name)
        dashboard.update(completed=True)

    dashboard.stop()

    findings = finding_list(exclude_fp=True)
    verified = finding_list(verified_only=True)
    print(f"""
╔══════════════════════════════════════════════════╗
║              HUNT COMPLETE                       ║
║  Total findings:    {len(findings):<28} ║
║  Verified:          {len(verified):<28} ║
║  Reports saved to:  {cfg.output_dir}            ║
╚══════════════════════════════════════════════════╝
""")
