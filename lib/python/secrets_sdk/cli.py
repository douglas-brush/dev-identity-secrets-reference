"""Click-based CLI for the secrets SDK.

Entry point: `secrets-sdk`
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from secrets_sdk import __version__


@click.group()
@click.version_option(version=__version__, prog_name="secrets-sdk")
def cli() -> None:
    """Developer identity and secrets management toolkit."""


@cli.command()
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    default=".",
    help="Repository root directory (default: current directory).",
)
@click.option("--json-output", "json_out", is_flag=True, help="Output results as JSON.")
def doctor(root: str, json_out: bool) -> None:
    """Validate repository structure, .sops.yaml, and Vault policies."""
    from secrets_sdk.config import validate_repo_structure

    issues = validate_repo_structure(root)
    if json_out:
        click.echo(json.dumps({"issues": issues, "count": len(issues)}, indent=2))
    elif issues:
        click.secho(f"Found {len(issues)} issue(s):\n", fg="yellow", bold=True)
        for i, issue in enumerate(issues, 1):
            click.echo(f"  {i}. {issue}")
        click.echo()
        sys.exit(1)
    else:
        click.secho("All checks passed.", fg="green", bold=True)


@cli.command("vault-health")
@click.option("--addr", envvar="VAULT_ADDR", default="http://127.0.0.1:8200", help="Vault address.")
@click.option("--json-output", "json_out", is_flag=True, help="Output results as JSON.")
def vault_health(addr: str, json_out: bool) -> None:
    """Check Vault connectivity and health status."""
    from secrets_sdk.vault import VaultClient

    client = VaultClient(addr=addr)
    report = client.health()

    if json_out:
        data = {
            "overall": report.overall_status.value,
            "checks": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "detail": c.detail,
                    "latency_ms": round(c.latency_ms, 2),
                }
                for c in report.checks
            ],
        }
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo(report.summary())
        click.echo()
        for check in report.checks:
            color = {"healthy": "green", "degraded": "yellow", "unhealthy": "red"}.get(
                check.status.value, "white"
            )
            click.secho(f"  {check.name}: {check.status.value}", fg=color)
            if check.detail:
                click.echo(f"    {check.detail}")
            if check.latency_ms > 0:
                click.echo(f"    latency: {check.latency_ms:.1f}ms")
        click.echo()

        from secrets_sdk.models import HealthStatus

        if report.overall_status == HealthStatus.UNHEALTHY:
            sys.exit(1)


@cli.command()
@click.argument("path", type=click.Path(exists=True, resolve_path=True))
@click.option(
    "--pattern",
    multiple=True,
    help="Only check specific pattern names (can be repeated).",
)
@click.option("--json-output", "json_out", is_flag=True, help="Output results as JSON.")
def scan(path: str, pattern: tuple[str, ...], json_out: bool) -> None:
    """Scan files or directories for plaintext secrets."""
    from secrets_sdk.config import scan_plaintext_secrets

    include = list(pattern) if pattern else None
    findings = scan_plaintext_secrets(path, include_patterns=include)

    if json_out:
        data = [
            {
                "file": f.file_path,
                "line": f.line_number,
                "pattern": f.pattern_name,
                "match": f.matched_text,
                "severity": f.severity,
            }
            for f in findings
        ]
        click.echo(json.dumps(data, indent=2))
    elif findings:
        click.secho(f"Found {len(findings)} potential secret(s):\n", fg="red", bold=True)
        for f in findings:
            sev_color = {"critical": "red", "high": "red", "medium": "yellow"}.get(f.severity, "white")
            click.secho(f"  [{f.severity.upper()}] {f.pattern_name}", fg=sev_color)
            click.echo(f"    {f.file_path}:{f.line_number}")
            click.echo(f"    matched: {f.matched_text}")
            click.echo()
        sys.exit(1)
    else:
        click.secho("No plaintext secrets found.", fg="green", bold=True)


@cli.command("rotate-check")
@click.option("--addr", envvar="VAULT_ADDR", default="http://127.0.0.1:8200", help="Vault address.")
@click.option("--path", "paths", multiple=True, required=True, help="Secret path(s) to check.")
@click.option("--max-age", type=float, default=90.0, help="Maximum age in days (default: 90).")
@click.option("--json-output", "json_out", is_flag=True, help="Output results as JSON.")
def rotate_check(addr: str, paths: tuple[str, ...], max_age: float, json_out: bool) -> None:
    """Check secret ages against rotation policy."""
    from secrets_sdk.vault import VaultClient
    from secrets_sdk.rotation import check_secret_age

    client = VaultClient(addr=addr)
    reports = []

    for p in paths:
        try:
            report = check_secret_age(client, p, max_age_days=max_age)
            reports.append(report)
        except Exception as exc:
            click.secho(f"Error checking {p}: {exc}", fg="red", err=True)

    if json_out:
        data = [
            {
                "path": r.path,
                "version": r.current_version,
                "age_days": round(r.age_days, 1),
                "max_age_days": r.max_age_days,
                "needs_rotation": r.needs_rotation,
                "detail": r.detail,
            }
            for r in reports
        ]
        click.echo(json.dumps(data, indent=2))
    else:
        any_overdue = False
        for r in reports:
            if r.needs_rotation:
                any_overdue = True
                click.secho(f"  OVERDUE  {r.path} ({r.age_days:.1f}d / {r.max_age_days:.0f}d max)", fg="red")
            elif r.age_days > r.max_age_days * 0.8:
                click.secho(f"  WARNING  {r.path} ({r.age_days:.1f}d / {r.max_age_days:.0f}d max)", fg="yellow")
            else:
                click.secho(f"  OK       {r.path} ({r.age_days:.1f}d / {r.max_age_days:.0f}d max)", fg="green")
            if r.detail:
                click.echo(f"           {r.detail}")
        if any_overdue:
            sys.exit(1)


@cli.command()
@click.argument("file_path", type=click.Path(exists=True, resolve_path=True))
@click.option("--output-format", type=click.Choice(["json", "yaml"]), default=None, help="Force output format.")
def decrypt(file_path: str, output_format: str) -> None:
    """Decrypt a SOPS-encrypted file and print the plaintext."""
    from secrets_sdk.sops import decrypt_file

    try:
        data = decrypt_file(file_path, output_format=output_format)
    except Exception as exc:
        click.secho(f"Decryption failed: {exc}", fg="red", err=True)
        sys.exit(1)

    fmt = output_format or "json"
    if fmt == "yaml":
        import yaml
        click.echo(yaml.safe_dump(data, default_flow_style=False))
    else:
        click.echo(json.dumps(data, indent=2))


# ------------------------------------------------------------------
# SIRM commands
# ------------------------------------------------------------------


@cli.command("sirm-init")
@click.option("--operator", required=True, help="Operator identity for the session.")
@click.option("--classification", default="UNCLASSIFIED", help="Session classification level.")
@click.option(
    "--session-dir",
    type=click.Path(resolve_path=True),
    default=".",
    help="Directory for session files (default: current directory).",
)
@click.option(
    "--repo-root",
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    default=".",
    help="Repository root for context loading.",
)
@click.option("--json-output", "json_out", is_flag=True, help="Output results as JSON.")
def sirm_init(operator: str, classification: str, session_dir: str, repo_root: str, json_out: bool) -> None:
    """Initialize a new SIRM incident response session."""
    from secrets_sdk.sirm import SIRMBootstrap

    bootstrap = SIRMBootstrap(
        operator=operator,
        classification=classification,
        session_dir=session_dir,
        repo_root=repo_root,
    )

    try:
        session = bootstrap.bootstrap()
    except RuntimeError as exc:
        click.secho(f"Bootstrap failed: {exc}", fg="red", err=True)
        sys.exit(1)

    report = bootstrap.report

    if json_out:
        data = {
            "session_id": session.session_id,
            "state": session.state.value,
            "operator": session.operator,
            "classification": session.classification,
            "phases": [p.model_dump(mode="json", exclude={"data"}) for p in report.phases],
            "overall": report.overall.value,
        }
        click.echo(json.dumps(data, indent=2, default=str))
    else:
        # Print the dashboard from phase 5
        for phase in report.phases:
            if phase.phase == 5 and "dashboard" in phase.data:
                click.echo(phase.data["dashboard"])
                break
        else:
            click.secho(f"Session {session.session_id} initialized ({session.state.value})", fg="green")


@cli.command("sirm-status")
@click.argument("session_file", type=click.Path(exists=True, resolve_path=True))
@click.option("--json-output", "json_out", is_flag=True, help="Output results as JSON.")
def sirm_status(session_file: str, json_out: bool) -> None:
    """Show status of a SIRM session."""
    from secrets_sdk.sirm import SIRMSession

    try:
        session = SIRMSession.load(session_file)
    except Exception as exc:
        click.secho(f"Failed to load session: {exc}", fg="red", err=True)
        sys.exit(1)

    record = session.record
    if json_out:
        data = {
            "session_id": record.session_id,
            "state": record.state.value,
            "operator": record.operator,
            "classification": record.classification,
            "created_at": record.created_at.isoformat(),
            "updated_at": record.updated_at.isoformat(),
            "log_entries": len(record.log),
            "seal_hash": record.seal_hash or None,
            "sealed_valid": session.verify_seal() if session.is_sealed else None,
        }
        click.echo(json.dumps(data, indent=2, default=str))
    else:
        color = {
            "ACTIVE": "green",
            "INITIALIZING": "yellow",
            "SUSPENDED": "yellow",
            "CLOSED": "white",
            "SEALED": "cyan",
        }.get(record.state.value, "white")
        click.secho(f"Session: {record.session_id}", bold=True)
        click.secho(f"  State: {record.state.value}", fg=color)
        click.echo(f"  Operator: {record.operator}")
        click.echo(f"  Classification: {record.classification}")
        click.echo(f"  Created: {record.created_at.isoformat()}")
        click.echo(f"  Updated: {record.updated_at.isoformat()}")
        click.echo(f"  Log entries: {len(record.log)}")
        if record.seal_hash:
            valid = session.verify_seal()
            seal_status = "VALID" if valid else "INVALID"
            seal_color = "green" if valid else "red"
            click.secho(f"  Seal: {seal_status} ({record.seal_hash[:16]}...)", fg=seal_color)


@cli.command("sirm-seal")
@click.argument("session_file", type=click.Path(exists=True, resolve_path=True))
@click.option("--reason", default="", help="Reason for closing and sealing.")
@click.option("--json-output", "json_out", is_flag=True, help="Output results as JSON.")
def sirm_seal(session_file: str, reason: str, json_out: bool) -> None:
    """Close and seal a SIRM session with tamper-evidence hash."""
    from secrets_sdk.sirm import SIRMSession

    try:
        session = SIRMSession.load(session_file)
    except Exception as exc:
        click.secho(f"Failed to load session: {exc}", fg="red", err=True)
        sys.exit(1)

    try:
        # Close first if active/suspended
        if session.state.value in ("ACTIVE", "SUSPENDED"):
            session.close(reason or "Closing for seal")
        seal_hash = session.seal()
    except Exception as exc:
        click.secho(f"Seal failed: {exc}", fg="red", err=True)
        sys.exit(1)

    if json_out:
        click.echo(json.dumps({
            "session_id": session.session_id,
            "state": session.state.value,
            "seal_hash": seal_hash,
        }, indent=2))
    else:
        click.secho(f"Session {session.session_id} sealed", fg="cyan", bold=True)
        click.echo(f"  Hash: {seal_hash}")


@cli.command("sirm-report")
@click.argument("session_file", type=click.Path(exists=True, resolve_path=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown"]),
    default="markdown",
    help="Report output format.",
)
def sirm_report(session_file: str, output_format: str) -> None:
    """Generate a report for a SIRM session."""
    from secrets_sdk.sirm import SIRMSession, SessionReport

    try:
        session = SIRMSession.load(session_file)
    except Exception as exc:
        click.secho(f"Failed to load session: {exc}", fg="red", err=True)
        sys.exit(1)

    report = SessionReport(session=session)

    if output_format == "json":
        click.echo(report.to_json())
    else:
        click.echo(report.to_markdown())


if __name__ == "__main__":
    cli()
