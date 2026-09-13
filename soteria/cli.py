import sys
import click
from pathlib import Path
from .auth import login, validate_session, save_session_token, load_session_token
from .config import load as load_config, write_default
from .database import init as init_db
from .kill_switch import init as init_kill_switch
from .modules.recon import ReconEngine
from .modules.scanner import VulnerabilityScanner
from .modules.fuzzer import CustomFuzzer
from .modules.report import ReportGenerator
from .modules.authorization.hunt import HuntManager

BANNER = r"""
=======================================
              SOTERIA
=======================================
   Continuous protection.
   Proven findings.
=======================================
"""


def get_soteria_dir():
    return Path.home() / ".soteria"


@click.group()
@click.pass_context
def main(ctx):
    soteria_dir = get_soteria_dir()
    soteria_dir.mkdir(parents=True, exist_ok=True)
    init_db(soteria_dir / "soteria.db")
    init_kill_switch(soteria_dir)
    cfg = load_config(soteria_dir / "config.yaml")

    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg
    ctx.obj["soteria_dir"] = soteria_dir

    token = load_session_token(soteria_dir)
    if token:
        session = validate_session(token)
        if session:
            ctx.obj["session"] = session
            return

    click.echo(BANNER)
    click.echo("RESTRICTED ACCESS")
    username = click.prompt("Username")
    password = click.prompt("Password", hide_input=True)
    ok, msg, session = login(username, password)
    if not ok:
        click.echo(f"[!] {msg}")
        sys.exit(1)
    save_session_token(session.token, soteria_dir)
    ctx.obj["session"] = session
    click.echo(f"[+] Authenticated as {username}")


@main.command()
def start():
    """Interactive guided hunting session."""
    from .interactive import interactive_hunt
    interactive_hunt()


@main.command()
@click.option("--domain", "-d", required=True)
def recon(domain):
    """Enumerate subdomains."""
    ReconEngine().run(domain)


@main.command()
@click.option("--target", "-t", required=True)
@click.option("--hunt", "-H", required=True, help="Hunt ID (required)")
def scan(target, hunt):
    """Run vulnerability scanning (requires hunt ID)."""
    try:
        scanner = VulnerabilityScanner(hunt_id=hunt)
        scanner.run(target)
    except Exception as e:
        click.echo(f"[!] {e}")
        sys.exit(1)


@main.command()
@click.option("--url", "-u", required=True)
def fuzz(url):
    """Custom fuzzing."""
    CustomFuzzer().run(url)


@main.command()
@click.option("--program", "-P", required=True)
def report(program):
    """Generate report."""
    ReportGenerator().run(program)


@main.command()
@click.argument("action")
def config(action):
    """Manage configuration."""
    if action == "init":
        write_default()
        click.echo("[+] Config written")
    elif action == "show":
        import yaml
        cfg = load_config()
        click.echo(yaml.dump(cfg.raw()))


@main.command()
@click.argument("action")
def train(action):
    """Training data management."""
    from .trainer import seed_database, export_jsonl
    if action == "collect":
        click.echo(f"[+] {seed_database()} entries")
    elif action == "export":
        path = get_soteria_dir() / "training_export.jsonl"
        click.echo(f"[+] Exported {export_jsonl(path)} entries")


@main.command()
@click.argument("action")
def admin(action):
    """Admin functions."""
    if action == "users":
        from .database import user_list
        for u in user_list():
            click.echo(f"  {u.username} ({u.role.value})")


@main.command()
@click.option("--domain", "-d", required=True)
@click.option("--org", "-o", default="default")
def verify(domain, org):
    """Request ownership verification."""
    from .modules.authorization.verifier import OwnershipVerifier
    token = OwnershipVerifier().generate_token(org, domain)
    click.echo("")
    click.echo("=" * 60)
    click.echo("  OWNERSHIP VERIFICATION")
    click.echo("=" * 60)
    click.echo(f"  Domain: {domain}")
    click.echo(f"  Token:  {token}")
    click.echo("")
    click.echo("  DNS METHOD:")
    click.echo(f"    Name:  _soteria-verify.{domain}")
    click.echo(f"    Value: {token}")
    click.echo("")
    click.echo("  FILE METHOD:")
    click.echo(f"    URL:  https://{domain}/.well-known/soteria-verify.txt")
    click.echo(f"    Content: {token}")
    click.echo("=" * 60)


@main.command()
@click.option("--domain", "-d", required=True)
@click.option("--token", "-t", required=True)
@click.option("--org", "-o", default="default")
def check(domain, token, org):
    """Check ownership verification."""
    from .modules.authorization.verifier import OwnershipVerifier
    verifier = OwnershipVerifier()
    click.echo(f"[*] Verifying {domain}...")
    result = verifier.verify_target(org, domain, token)
    if result["verified"]:
        click.echo(f"[+] VERIFIED via {result['method'].upper()}")
    else:
        click.echo(f"[-] NOT VERIFIED: {result.get('error', 'unknown')}")


# ── HUNT COMMANDS ──

@main.group()
def hunt():
    """Manage hunt IDs (required for scans)."""
    pass


@hunt.command("create")
@click.option("--org", "-o", default="default")
@click.option("--name", "-n", default="engagement", help="Hunt name")
@click.option("--domains", "-D", required=True, help="Comma-separated target domains")
@click.option("--authorized-by", "-A", required=True, help="Who authorized this hunt")
@click.option("--valid-days", "-V", default=365, help="Valid for N days")
def hunt_create(org, name, domains, authorized_by, valid_days):
    """Create a new hunt ID."""
    from datetime import datetime, timedelta, timezone
    hunt_id = HuntManager.generate_id(org, name)
    valid_until = (datetime.now(timezone.utc) + timedelta(days=valid_days)).isoformat()
    domain_list = [d.strip() for d in domains.split(",") if d.strip()]

    manager = HuntManager(db=__import__("soteria.database", fromlist=["_connect"])._connect())
    ok = manager.create_hunt(
        hunt_id=hunt_id,
        org_id=org,
        target_domains=domain_list,
        scope_document="",
        authorized_by=authorized_by,
        valid_until=valid_until,
    )
    if ok:
        click.echo("")
        click.echo("=" * 60)
        click.echo("  HUNT CREATED")
        click.echo("=" * 60)
        click.echo(f"  Hunt ID:        {hunt_id}")
        click.echo(f"  Organization:   {org}")
        click.echo(f"  Target domains: {', '.join(domain_list)}")
        click.echo(f"  Authorized by:  {authorized_by}")
        click.echo(f"  Valid until:    {valid_until}")
        click.echo("")
        click.echo(f"  Use this hunt ID for scans:")
        click.echo(f"    soteria scan -t https://target.com --hunt {hunt_id}")
        click.echo("=" * 60)
    else:
        click.echo("[!] Failed to create hunt")


@hunt.command("list")
def hunt_list():
    """List all hunts."""
    import sqlite3
    from pathlib import Path
    conn = sqlite3.connect(Path.home() / ".soteria" / "soteria.db")
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM hunts ORDER BY created_at DESC").fetchall()
    if not rows:
        click.echo("[!] No hunts created yet")
    for r in rows:
        status = "ACTIVE" if r["active"] else "REVOKED"
        click.echo(f"  [{status}] {r['hunt_id']}")
        click.echo(f"    Org: {r['org_id']} | Domains: {r['target_domains']}")
        click.echo(f"    Authorized by: {r['authorized_by']}")
        click.echo()
    conn.close()


@hunt.command("revoke")
@click.argument("hunt_id")
def hunt_revoke(hunt_id):
    """Revoke a hunt ID."""
    manager = HuntManager(db=__import__("soteria.database", fromlist=["_connect"])._connect())
    if manager.revoke(hunt_id):
        click.echo(f"[+] Revoked: {hunt_id}")
    else:
        click.echo(f"[!] Failed to revoke: {hunt_id}")


if __name__ == "__main__":
    main()
