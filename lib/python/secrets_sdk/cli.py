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
@click.option("--output-format", type=click.Choice(["json", "yaml"]), default="", help="Force output format.")
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


if __name__ == "__main__":
    cli()
