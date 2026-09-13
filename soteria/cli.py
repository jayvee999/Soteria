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
    """Enumerate subdomains and detect live hosts."""
    engine = ReconEngine()
    engine.run(domain)


@main.command()
@click.option("--target", "-t", required=True)
def scan(target):
    """Run vulnerability scanning."""
    scanner = VulnerabilityScanner()
    scanner.run(target)


@main.command()
@click.option("--url", "-u", required=True)
def fuzz(url):
    """Custom fuzzing."""
    fuzzer = CustomFuzzer()
    fuzzer.run(url)


@main.command()
@click.option("--program", "-P", required=True)
def report(program):
    """Generate report."""
    gen = ReportGenerator()
    gen.run(program)


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
        count = seed_database()
        click.echo(f"[+] {count} entries")
    elif action == "export":
        path = get_soteria_dir() / "training_export.jsonl"
        count = export_jsonl(path)
        click.echo(f"[+] Exported {count} entries")


@main.command()
@click.argument("action")
def admin(action):
    """Admin functions."""
    if action == "users":
        from .database import user_list
        for u in user_list():
            click.echo(f"  {u.username} ({u.role.value})")


@main.command()
@click.option("--domain", "-d", required=True, help="Domain to verify")
@click.option("--org", "-o", default="default", help="Organization ID")
def verify(domain, org):
    """Request ownership verification for a target domain."""
    from .modules.authorization.verifier import OwnershipVerifier
    verifier = OwnershipVerifier()
    token = verifier.generate_token(org, domain)

    click.echo("")
    click.echo("=" * 60)
    click.echo("  SOTERIA — OWNERSHIP VERIFICATION")
    click.echo("=" * 60)
    click.echo("")
    click.echo(f"  Domain: {domain}")
    click.echo(f"  Token:  {token}")
    click.echo("")
    click.echo("  CHOOSE ONE METHOD:")
    click.echo("")
    click.echo("  [DNS METHOD]")
    click.echo(f"    Add a TXT record:")
    click.echo(f"    Name:  _soteria-verify.{domain}")
    click.echo(f"    Value: {token}")
    click.echo("")
    click.echo("  [FILE METHOD]")
    click.echo(f"    URL:  https://{domain}/.well-known/soteria-verify.txt")
    click.echo(f"    Content: {token}")
    click.echo("")
    click.echo("  After setup, run:")
    click.echo(f"    soteria check -d {domain} -t {token}")
    click.echo("")
    click.echo("=" * 60)


@main.command()
@click.option("--domain", "-d", required=True, help="Domain to check")
@click.option("--token", "-t", required=True, help="Verification token")
@click.option("--org", "-o", default="default", help="Organization ID")
def check(domain, token, org):
    """Check ownership verification."""
    from .modules.authorization.verifier import OwnershipVerifier
    verifier = OwnershipVerifier()
    click.echo(f"[*] Verifying {domain}...")
    result = verifier.verify_target(org, domain, token)
    if result["verified"]:
        click.echo(f"[+] VERIFIED via {result['method'].upper()}")
        click.echo(f"[+] Scans authorized for {domain}")
    else:
        click.echo(f"[-] NOT VERIFIED: {result.get('error', 'unknown')}")
        click.echo(f"[!] Check DNS TTL (may take 5-10 min to propagate)")

@main.command()
@click.option("--url", "-u", required=True, help="Slack webhook URL")
@click.option("--org", "-o", default="default", help="Organization ID")
def slack(url, org):
    """Configure Slack webhook for alerts."""
    import json
    from pathlib import Path
    config_path = get_soteria_dir() / "integrations.json"
    config = {}
    if config_path.exists():
        config = json.loads(config_path.read_text())
    config.setdefault(org, {})
    config[org]["slack_webhook"] = url
    config_path.write_text(json.dumps(config, indent=2))
    click.echo(f"[+] Slack webhook saved for {org}")


@main.command()
@click.option("--title", "-t", default="Test Finding", help="Finding title")
@click.option("--org", "-o", default="default", help="Organization ID")
def slacktest(title, org):
    """Send a test message to Slack."""
    import json
    from .integrations.slack import SlackNotifier
    from .models import Finding, Severity
    config_path = get_soteria_dir() / "integrations.json"
    if not config_path.exists():
        click.echo("[!] No Slack webhook configured. Run: soteria slack -u URL")
        return
    config = json.loads(config_path.read_text())
    webhook = config.get(org, {}).get("slack_webhook")
    if not webhook:
        click.echo(f"[!] No Slack webhook for {org}")
        return
    finding = Finding(
        url="https://example.com/api/users/123",
        type="idor",
        severity=Severity.HIGH,
        title=title,
        description="Test finding from Soteria. This confirms Slack integration works.",
        curl_command="curl https://example.com/api/users/124",
        verified=True,
    )
    notifier = SlackNotifier(webhook)
    if notifier.send(finding):
        click.echo("[+] Test message sent to Slack")
    else:
        click.echo("[-] Failed to send Slack message")

if __name__ == "__main__":
    main()
