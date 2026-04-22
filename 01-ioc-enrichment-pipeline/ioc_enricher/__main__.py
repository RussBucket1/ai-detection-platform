"""CLI entry point for the IOC enrichment pipeline."""
from __future__ import annotations

import asyncio
import csv
import io
import sys
from pathlib import Path
from typing import Any

import click
import orjson
from rich.console import Console
from rich.table import Table

from ioc_enricher import __version__
from ioc_enricher.ioc_parser import IOCParser
from ioc_enricher.models.ioc import EnrichedIOC, RiskBand
from ioc_enricher.pipeline import EnrichmentPipeline
from ioc_enricher.utils.config import load_config
from ioc_enricher.utils.logger import configure_logging, get_logger

_console = Console(stderr=True)
_out_console = Console()
_log = get_logger(__name__)

_BAND_COLORS: dict[str, str] = {
    RiskBand.CRITICAL.value: "bold red",
    RiskBand.HIGH.value: "red",
    RiskBand.MEDIUM.value: "yellow",
    RiskBand.LOW.value: "green",
    RiskBand.INFO.value: "dim white",
    RiskBand.UNKNOWN.value: "dim white",
}


@click.group()
@click.option("--config", "config_path", default=None, help="Path to config YAML file.")
@click.option("--log-level", default=None, help="Override log level (DEBUG/INFO/WARNING/ERROR).")
@click.option("--json-logs/--no-json-logs", default=False, help="Emit structured JSON logs.")
@click.pass_context
def cli(ctx: click.Context, config_path: str | None, log_level: str | None, json_logs: bool) -> None:
    """IOC Enrichment Pipeline — threat intelligence enrichment for Detection Engineering."""
    ctx.ensure_object(dict)
    app_config = load_config(config_path)
    if log_level:
        app_config.pipeline.log_level = log_level.upper()
    configure_logging(app_config.pipeline.log_level, json_logs=json_logs)
    ctx.obj["config"] = app_config


@cli.command()
@click.option("--input-file", "-f", type=click.Path(exists=True), default=None,
              help="File containing IOCs (one per line, # comments ignored).")
@click.option("--ioc", "-i", "single_ioc", multiple=True,
              help="Single IOC value to enrich (repeatable).")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file path (default: stdout).")
@click.option("--output-format", type=click.Choice(["table", "json", "ndjson", "csv"]),
              default="table", help="Output format.")
@click.option("--min-score", type=int, default=0,
              help="Minimum risk score filter (0-100).")
@click.option("--source", default="cli", help="Source label for parsed IOCs.")
@click.pass_context
def enrich(
    ctx: click.Context,
    input_file: str | None,
    single_ioc: tuple[str, ...],
    output: str | None,
    output_format: str,
    min_score: int,
    source: str,
) -> None:
    """Enrich IOCs from a file and/or inline values, outputting in various formats."""
    config = ctx.obj["config"]
    parser = IOCParser()
    iocs = []

    if input_file:
        iocs.extend(parser.parse_file(input_file, source=source))
    for val in single_ioc:
        parsed = parser.parse(val, source=source)
        if parsed:
            iocs.append(parsed)

    if not iocs:
        _console.print("[yellow]No IOCs to enrich.[/yellow]")
        sys.exit(0)

    _console.print(f"[bold]Enriching {len(iocs)} IOC(s) with pipeline v{__version__}...[/bold]")

    async def _run() -> list[EnrichedIOC]:
        async with EnrichmentPipeline.from_config(config) as pipeline:
            return await pipeline.enrich_batch(iocs, min_risk_score=min_score)

    results = asyncio.run(_run())

    out_path = Path(output) if output else None

    if output_format == "table":
        _print_summary_table(results, out_path)
    elif output_format == "json":
        _write_json(results, out_path)
    elif output_format == "ndjson":
        _write_ndjson(results, out_path)
    elif output_format == "csv":
        _write_csv(results, out_path)

    _console.print(f"\n[bold green]Done.[/bold green] {len(results)} result(s) produced.")


@cli.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Print the pipeline version and exit."""
    click.echo(f"ioc-enricher {__version__}")


def _write_json(results: list[EnrichedIOC], path: Path | None) -> None:
    """Write enriched results as a pretty-printed JSON array."""
    payload = [r.model_dump(mode="json") for r in results]

    def _default(obj: Any) -> str:
        return str(obj)

    text = orjson.dumps(payload, option=orjson.OPT_INDENT_2, default=_default).decode()
    if path:
        path.write_text(text, encoding="utf-8")
        _console.print(f"JSON written to [cyan]{path}[/cyan]")
    else:
        _out_console.print(text)


def _write_ndjson(results: list[EnrichedIOC], path: Path | None) -> None:
    """Write enriched results as newline-delimited ECS JSON records."""
    def _default(obj: Any) -> str:
        return str(obj)

    lines = [orjson.dumps(r.to_ecs(), default=_default).decode() for r in results]
    content = "\n".join(lines) + "\n"
    if path:
        path.write_text(content, encoding="utf-8")
        _console.print(f"NDJSON written to [cyan]{path}[/cyan]")
    else:
        _out_console.print(content)


def _write_csv(results: list[EnrichedIOC], path: Path | None) -> None:
    """Write enriched results as CSV with key fields."""
    fieldnames = [
        "ioc_value", "ioc_type", "risk_score", "risk_band", "confidence",
        "source", "providers_queried", "providers_failed",
        "mitre_techniques", "tags", "enriched_at",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for r in results:
        writer.writerow({
            "ioc_value": r.ioc.value,
            "ioc_type": r.ioc.ioc_type.value,
            "risk_score": r.risk.score if r.risk else 0,
            "risk_band": r.risk.band.value if r.risk else "UNKNOWN",
            "confidence": round(r.risk.confidence, 4) if r.risk else 0.0,
            "source": r.ioc.source,
            "providers_queried": "|".join(r.providers_queried),
            "providers_failed": "|".join(r.providers_failed),
            "mitre_techniques": "|".join(m.technique_id for m in r.mitre_techniques),
            "tags": "|".join(r.all_tags[:5]),
            "enriched_at": r.enriched_at.isoformat(),
        })
    content = buf.getvalue()
    if path:
        path.write_text(content, encoding="utf-8")
        _console.print(f"CSV written to [cyan]{path}[/cyan]")
    else:
        _out_console.print(content)


def _print_summary_table(results: list[EnrichedIOC], path: Path | None) -> None:
    """Render enriched results as a Rich table with color-coded risk bands."""
    table = Table(
        title="IOC Enrichment Results",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("IOC Value", style="cyan", no_wrap=True, max_width=40)
    table.add_column("Type", style="bold")
    table.add_column("Risk Score", justify="right")
    table.add_column("Band", justify="center")
    table.add_column("Confidence", justify="right")
    table.add_column("MITRE (top 3)")
    table.add_column("Tags (top 5)")

    for r in results:
        score = r.risk.score if r.risk else 0
        band = r.risk.band.value if r.risk else "UNKNOWN"
        confidence = f"{r.risk.confidence:.0%}" if r.risk else "0%"
        color = _BAND_COLORS.get(band, "white")
        mitre_str = ", ".join(m.technique_id for m in r.mitre_techniques[:3]) or "-"
        tags_str = ", ".join(r.all_tags[:5]) or "-"

        table.add_row(
            r.ioc.value,
            r.ioc.ioc_type.value,
            f"[{color}]{score}[/{color}]",
            f"[{color}]{band}[/{color}]",
            confidence,
            mitre_str,
            tags_str,
        )

    if path:
        with path.open("w", encoding="utf-8") as fh:
            console = Console(file=fh, highlight=False)
            console.print(table)
        _console.print(f"Table written to [cyan]{path}[/cyan]")
    else:
        _out_console.print(table)


def main() -> None:
    """Entry point for the ioc-enricher CLI command."""
    cli(obj={})


if __name__ == "__main__":
    main()
