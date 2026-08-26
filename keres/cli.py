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
╔═══════════════════════════════════════╗
║                                       ║
║              ☽ ✚ ☾                    ║
║                 \│/                   ║
║                  │                    ║
║             ╔════╧════╗               ║
║             ║  KERES  ║               ║
║             ╚════╤════╝               ║
║                  │                    ║
║                                       ║
║      "The swarm sees everything."     ║
║                                       ║
╚═══════════════════════════════════════╝
"""


def get_keres_dir():
    return Path.home() / ".keres"


@click.group()
@click.pass_context
def main(ctx):
    keres_dir = get_keres_dir()
    keres_dir.mkdir(parents=True, exist_ok=True)
    init_db(keres_dir / "keres.db")
    init_kill_switch(keres_dir)
    cfg = load_config(keres_dir / "config.yaml")

    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg
    ctx.obj["keres_dir"] = keres_dir

    token = load_session_token(keres_dir)
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

    save_session_token(session.token, keres_dir)
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
@click.option("--templates", "-T", multiple=True)
@click.option("--severity", "-s")
def scan(target, templates, severity):
    """Run vulnerability scanning."""
    scanner = VulnerabilityScanner()
    scanner.run(target, list(templates) if templates else None, severity)


@main.command()
@click.option("--url", "-u", required=True)
@click.option("--params", "-p", multiple=True)
def fuzz(url, params):
    """Custom fuzzing for injection vulnerabilities."""
    fuzzer = CustomFuzzer()
    fuzzer.run(url, list(params) if params else None)


@main.command()
@click.option("--program", "-P", required=True)
@click.option("--format", "-f", default="markdown")
def report(program, format):
    """Generate report from verified findings."""
    gen = ReportGenerator()
    gen.run(program, format)


@main.command()
@click.argument("action")
def config(action):
    """Manage configuration."""
    if action == "show":
        import yaml
        cfg = load_config()
        click.echo(yaml.dump(cfg.raw()))
    elif action == "init":
        write_default()
        click.echo("[+] Default config written")
    else:
        click.echo(f"[!] Unknown config action: {action}")


@main.command()
@click.argument("action")
@click.option("--key", "-k")
def license(action, key):
    """License management."""
    from .auth import activate_license, generate_license_key
    if action == "activate" and key:
        ok, msg, _ = activate_license(key)
        click.echo(f"[{'+' if ok else '!'}] {msg}")
    elif action == "generate":
        plain_key, _ = generate_license_key()
        click.echo(f"[+] License: {plain_key}")


@main.command()
@click.argument("action")
def train(action):
    """Training data management."""
    from .trainer import seed_database, export_jsonl
    if action == "collect":
        count = seed_database()
        click.echo(f"[+] {count} entries")
    elif action == "export":
        path = get_keres_dir() / "training_export.jsonl"
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


if __name__ == "__main__":
    main()
