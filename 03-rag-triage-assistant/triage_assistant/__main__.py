"""Click CLI for the RAG alert triage assistant."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from triage_assistant import __version__
from triage_assistant.models.alert import AlertSeverity, AlertSource, RawAlert
from triage_assistant.utils.config import load_config
from triage_assistant.utils.logger import configure_logging

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

console = Console()

_SEVERITY_COLOURS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "informational": "dim",
}

_VERDICT_COLOURS = {
    "true_positive": "bold red",
    "likely_true_positive": "red",
    "needs_investigation": "yellow",
    "likely_false_positive": "cyan",
    "false_positive": "green",
}

_ACTION_COLOURS = {
    "escalate_immediately": "bold red",
    "investigate": "yellow",
    "monitor": "cyan",
    "suppress": "dim",
    "close": "green",
}


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------


@click.group()
@click.option("--config", "config_path", default=None, help="Path to config YAML file")
@click.option(
    "--log-level",
    default=None,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    help="Override log level",
)
@click.option("--json-logs", is_flag=True, default=False, help="Emit structured JSON logs")
@click.pass_context
def cli(ctx: click.Context, config_path: str | None, log_level: str | None, json_logs: bool) -> None:
    """AI Alert Triage Assistant — RAG-based SIEM alert analysis."""
    ctx.ensure_object(dict)
    config = load_config(config_path)
    if log_level:
        config.triage.log_level = log_level
    configure_logging(config.triage.log_level, json_logs=json_logs)
    ctx.obj["config"] = config


# ---------------------------------------------------------------------------
# triage command
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--alert-json", default=None, help="JSON string of a RawAlert")
@click.option("--file", "-f", "alert_file", default=None, type=click.Path(exists=True), help="Path to JSON file containing a RawAlert")
@click.option("--title", "-t", default=None, help="Alert title (builds a minimal inline alert)")
@click.option("--source-ip", default=None, help="Source IP for inline alert")
@click.option("--command-line", default=None, help="Process command line for inline alert")
@click.option(
    "--severity",
    default="medium",
    type=click.Choice([s.value for s in AlertSeverity], case_sensitive=False),
    help="Severity for inline alert",
)
@click.pass_context
def triage(
    ctx: click.Context,
    alert_json: str | None,
    alert_file: str | None,
    title: str | None,
    source_ip: str | None,
    command_line: str | None,
    severity: str,
) -> None:
    """Triage a SIEM alert through the RAG pipeline and display results."""
    from triage_assistant.assistant import TriageAssistant

    config = ctx.obj["config"]

    # Build the RawAlert from whichever input was provided
    alert: RawAlert
    if alert_json:
        try:
            alert = RawAlert.model_validate_json(alert_json)
        except Exception as exc:
            console.print(f"[red]Invalid alert JSON: {exc}[/red]")
            sys.exit(1)
    elif alert_file:
        try:
            alert = RawAlert.model_validate_json(Path(alert_file).read_text())
        except Exception as exc:
            console.print(f"[red]Failed to load alert file: {exc}[/red]")
            sys.exit(1)
    elif title:
        alert = RawAlert(
            title=title,
            description=title,
            severity=AlertSeverity(severity),
            source=AlertSource.manual,
            source_ip=source_ip,
            command_line=command_line,
        )
    else:
        console.print("[red]Provide --alert-json, --file, or --title.[/red]")
        sys.exit(1)

    with console.status("[bold cyan]Triaging alert…[/bold cyan]"):
        assistant = TriageAssistant(config)
        result = assistant.triage_sync(alert)

    # -----------------------------------------------------------------------
    # Rich display
    # -----------------------------------------------------------------------
    verdict_colour = _VERDICT_COLOURS.get(result.verdict.value, "white")
    severity_colour = _SEVERITY_COLOURS.get(result.severity_assessment.value, "white")
    action_colour = _ACTION_COLOURS.get(result.recommended_action.value, "white")

    header = (
        f"[{verdict_colour}]Verdict: {result.verdict.value.replace('_', ' ').upper()}[/{verdict_colour}]  "
        f"[{severity_colour}]Severity: {result.severity_assessment.value.upper()}[/{severity_colour}]  "
        f"[bold]Confidence: {result.confidence:.0%}[/bold]  "
        f"[{action_colour}]Action: {result.recommended_action.value.replace('_', ' ').upper()}[/{action_colour}]"
    )

    console.print()
    console.print(Panel(header, title=f"[bold]Triage Result — {alert.title}[/bold]", expand=True))
    console.print()
    console.print(Panel(result.summary, title="Summary", expand=False))
    console.print()

    if result.mitre_techniques:
        mitre_table = Table(title="MITRE ATT&CK Techniques", show_header=True)
        mitre_table.add_column("Technique ID", style="cyan")
        mitre_table.add_column("Name")
        mitre_table.add_column("Tactic")
        mitre_table.add_column("Confidence", justify="right")
        for t in result.mitre_techniques:
            mitre_table.add_row(
                t.technique_id,
                t.technique_name,
                t.tactic,
                f"{t.confidence:.0%}",
            )
        console.print(mitre_table)
        console.print()

    if result.context_matches:
        ctx_table = Table(title="RAG Context Matches", show_header=True)
        ctx_table.add_column("Source", style="dim")
        ctx_table.add_column("Title")
        ctx_table.add_column("Relevance", justify="right")
        for m in result.context_matches[:10]:
            ctx_table.add_row(m.source, m.title, f"{m.relevance_score:.2f}")
        console.print(ctx_table)
        console.print()

    if result.recommended_searches:
        console.print("[bold]Recommended Follow-Up Searches:[/bold]")
        for i, search in enumerate(result.recommended_searches, 1):
            console.print(f"  {i}. [dim]{search}[/dim]")
        console.print()

    console.print(Panel(result.analyst_notes, title="Analyst Notes", expand=True))

    # Save JSON output
    output_dir = Path("./output")
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / f"{result.alert_id}_triage.json"
    output_file.write_text(result.model_dump_json(indent=2))
    console.print(f"\n[dim]Saved to {output_file}[/dim]")


# ---------------------------------------------------------------------------
# ingest command group
# ---------------------------------------------------------------------------


@cli.group()
def ingest() -> None:
    """Ingest knowledge base data into the vector store."""


@ingest.command("iocs")
@click.option("--path", required=True, help="Path to IOC JSON file or directory")
@click.pass_context
def ingest_iocs(ctx: click.Context, path: str) -> None:
    """Ingest enriched IOC data from module 01 output."""
    import asyncio

    from triage_assistant.assistant import TriageAssistant

    config = ctx.obj["config"]
    with console.status("[bold cyan]Ingesting IOCs…[/bold cyan]"):
        assistant = TriageAssistant(config)
        count = asyncio.run(assistant.ingest_iocs(path))
    console.print(f"[green]✓[/green] Ingested [bold]{count}[/bold] IOC document(s)")


@ingest.command("sigma")
@click.option("--path", required=True, help="Path to SIGMA rule YAML file or directory")
@click.pass_context
def ingest_sigma(ctx: click.Context, path: str) -> None:
    """Ingest SIGMA detection rules from module 02 output."""
    import asyncio

    from triage_assistant.assistant import TriageAssistant

    config = ctx.obj["config"]
    with console.status("[bold cyan]Ingesting SIGMA rules…[/bold cyan]"):
        assistant = TriageAssistant(config)
        count = asyncio.run(assistant.ingest_sigma_rules(path))
    console.print(f"[green]✓[/green] Ingested [bold]{count}[/bold] SIGMA rule(s)")


@ingest.command("mitre")
@click.option("--cache-path", default=None, help="Local path to cache the MITRE STIX bundle")
@click.pass_context
def ingest_mitre(ctx: click.Context, cache_path: str | None) -> None:
    """Download and ingest MITRE ATT&CK Enterprise technique data."""
    import asyncio

    from triage_assistant.assistant import TriageAssistant

    config = ctx.obj["config"]
    with console.status("[bold cyan]Downloading and ingesting MITRE ATT&CK…[/bold cyan]"):
        assistant = TriageAssistant(config)
        count = asyncio.run(assistant.ingest_mitre(cache_path=cache_path))
    console.print(f"[green]✓[/green] Ingested [bold]{count}[/bold] MITRE ATT&CK technique(s)")


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show knowledge base collection sizes and readiness."""
    from triage_assistant.assistant import TriageAssistant
    from triage_assistant.retrieval.vector_store import (
        COLLECTION_IOCS,
        COLLECTION_MITRE,
        COLLECTION_SIGMA,
    )

    config = ctx.obj["config"]
    assistant = TriageAssistant(config)
    stats = assistant.get_knowledge_base_stats()
    collection_counts: dict[str, int] = stats.get("collections", {})

    table = Table(title="Knowledge Base Status", show_header=True)
    table.add_column("Collection")
    table.add_column("Documents", justify="right")
    table.add_column("Status")

    for name in (COLLECTION_IOCS, COLLECTION_SIGMA, COLLECTION_MITRE):
        count = collection_counts.get(name, 0)
        ready_str = "[green]✓ Ready[/green]" if count > 0 else "[red]✗ Empty[/red]"
        table.add_row(name, str(count), ready_str)

    console.print(table)
    console.print(
        f"\n[dim]Persist directory: {stats.get('persist_directory')} | "
        f"Embedding model: {stats.get('embedding_model')}[/dim]"
    )


# ---------------------------------------------------------------------------
# serve command
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True, help="Bind host")
@click.option("--port", default=8000, show_default=True, help="Bind port")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload for development")
@click.pass_context
def serve(ctx: click.Context, host: str, port: int, reload: bool) -> None:
    """Start the FastAPI REST API server."""
    console.print(
        f"[bold cyan]Starting triage-assistant API on http://{host}:{port}[/bold cyan]"
    )
    uvicorn.run(
        "triage_assistant.api:app",
        host=host,
        port=port,
        reload=reload,
        log_level="warning",
    )


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------


@cli.command()
def version() -> None:
    """Print the triage-assistant version."""
    console.print(f"triage-assistant {__version__}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Package entry point registered in setup.py."""
    cli(obj={})


if __name__ == "__main__":
    main()
