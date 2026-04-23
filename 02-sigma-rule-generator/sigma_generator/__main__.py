"""CLI entry point for the SIGMA Rule Generator."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

from sigma_generator import __version__
from sigma_generator.generator import SigmaGenerator
from sigma_generator.models.sigma import GenerationResult, SigmaRule, ValidationResult
from sigma_generator.utils.config import AppConfig, load_config
from sigma_generator.utils.logger import configure_logging, get_logger
from sigma_generator.validator import SigmaValidator

console = Console(stderr=False)
err_console = Console(stderr=True)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.option(
    "--config",
    "config_path",
    default=None,
    type=click.Path(exists=False),
    help="Path to config YAML file.",
)
@click.option(
    "--log-level",
    default=None,
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    help="Override log level.",
)
@click.option("--json-logs/--no-json-logs", default=True, help="Emit JSON structured logs.")
@click.pass_context
def cli(ctx: click.Context, config_path: str | None, log_level: str | None, json_logs: bool) -> None:
    """AI-powered SIGMA detection rule generator.

    Converts unstructured threat intelligence into production-ready SIGMA rules
    with MITRE ATT&CK mapping, false positive guidance, and confidence scores.
    """
    ctx.ensure_object(dict)
    config = load_config(config_path)
    if log_level:
        config.generator.log_level = log_level
    configure_logging(config.generator.log_level, json_logs=json_logs)
    ctx.obj["config"] = config


# ---------------------------------------------------------------------------
# generate command
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--input", "-i", "input_path", type=click.Path(exists=True), help="Input file path.")
@click.option("--text", "-t", "input_text", default=None, help="Inline threat intelligence text.")
@click.option(
    "--type",
    "input_type",
    default=None,
    type=click.Choice(["threat_report", "cve", "ioc_list", "log_snippet", "freeform"]),
    help="Force input type (auto-detected if omitted).",
)
@click.option(
    "--output", "-o", "output_dir", default=None, help="Output directory (default: ./output)."
)
@click.option(
    "--format",
    "-f",
    "output_format",
    default="yaml",
    type=click.Choice(["yaml", "json", "both"]),
    help="Output file format.",
)
@click.option("--author", default=None, help="Override rule author field.")
@click.option(
    "--min-confidence",
    "min_confidence",
    default=None,
    type=click.FloatRange(0.0, 1.0),
    help="Filter rules below this confidence score (0.0–1.0).",
)
@click.option("--no-validate", "skip_validate", is_flag=True, help="Skip validation step.")
@click.pass_context
def generate(
    ctx: click.Context,
    input_path: str | None,
    input_text: str | None,
    input_type: str | None,
    output_dir: str | None,
    output_format: str,
    author: str | None,
    min_confidence: float | None,
    skip_validate: bool,
) -> None:
    """Generate SIGMA rules from threat intelligence.

    Provide either --input (file) or --text (inline string). The input type
    is auto-detected but can be overridden with --type.
    """
    config: AppConfig = ctx.obj["config"]

    if not input_path and not input_text:
        err_console.print("[red]Error:[/] Provide --input or --text.", highlight=False)
        sys.exit(1)

    if skip_validate:
        config.generator.validate_output = False
    if min_confidence is not None:
        config.generator.min_confidence_threshold = min_confidence
    if output_dir:
        config.output.output_dir = output_dir

    gen = SigmaGenerator(config)

    import asyncio

    with console.status("[bold cyan]Generating SIGMA rules…[/]", spinner="dots"):
        if input_path:
            result: GenerationResult = asyncio.run(
                gen.generate_from_file(input_path, input_type=input_type, author=author)
            )
        else:
            result = gen.generate_sync(input_text, input_type=input_type, author=author)  # type: ignore[arg-type]

    _display_generation_result(result, config, output_format)

    if not result.success or not result.rules:
        sys.exit(1)


def _display_generation_result(
    result: GenerationResult, config: AppConfig, output_format: str
) -> None:
    """Render generation result as a Rich table and write output files."""
    if not result.success:
        err_console.print(
            Panel(
                f"[red bold]Generation failed[/]\n\n{result.error}",
                title="Error",
                border_style="red",
            )
        )
        return

    if not result.rules:
        console.print(
            Panel(
                "[yellow]No rules were generated or all rules were filtered out.[/]\n"
                "Try adjusting --min-confidence or --no-validate.",
                title="No Rules",
                border_style="yellow",
            )
        )
        return

    table = Table(
        title=f"Generated SIGMA Rules  [dim]({result.model_used}  {result.generation_time_ms:.0f}ms)[/]",
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Title", style="bold", min_width=30)
    table.add_column("Level", justify="center", width=12)
    table.add_column("Confidence", justify="center", width=12)
    table.add_column("MITRE Techniques", width=22)
    table.add_column("Logsource", width=24)
    table.add_column("Warnings", width=16)

    validator = SigmaValidator()
    output_paths: list[str] = []

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    out_dir = Path(config.output.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for rule in result.rules:
        level_color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "informational": "dim",
        }.get(rule.level.value, "white")

        confidence_color = "green" if rule.confidence_score >= 0.7 else "yellow" if rule.confidence_score >= 0.4 else "red"

        validation = validator.validate_rule(rule)
        warn_text = f"[yellow]{len(validation.warnings)}[/]" if validation.warnings else "[green]0[/]"

        techniques = ", ".join(
            m.technique_id for m in rule.mitre_attack[:2]
        ) or "[dim]None[/]"
        if len(rule.mitre_attack) > 2:
            techniques += f" +{len(rule.mitre_attack) - 2}"

        logsource_parts = [
            p for p in [rule.logsource.category, rule.logsource.product, rule.logsource.service]
            if p
        ]
        logsource_str = " / ".join(logsource_parts) or "[dim]unset[/]"

        table.add_row(
            rule.title,
            f"[{level_color}]{rule.level.value.upper()}[/]",
            f"[{confidence_color}]{rule.confidence_score:.0%}[/]",
            techniques,
            logsource_str,
            warn_text,
        )

        paths = _write_rule_output(rule, out_dir, timestamp, output_format, config)
        output_paths.extend(paths)

    console.print(table)

    if result.source_summary:
        console.print(
            Panel(result.source_summary, title="Analysis Summary", border_style="blue", padding=(0, 1))
        )

    if output_paths:
        console.print("\n[bold green]Output files:[/]")
        for p in output_paths:
            console.print(f"  [cyan]{p}[/]")


def _write_rule_output(
    rule: SigmaRule,
    out_dir: Path,
    timestamp: str,
    output_format: str,
    config: AppConfig,
) -> list[str]:
    """Write rule to YAML and/or JSON files, returning paths written."""
    written: list[str] = []
    stem = f"{rule.name}_{timestamp}"

    if output_format in {"yaml", "both"}:
        yaml_path = out_dir / f"{stem}.yml"
        yaml_path.write_text(rule.to_sigma_yaml(), encoding="utf-8")
        written.append(str(yaml_path))

    if output_format in {"json", "both"}:
        json_path = out_dir / f"{stem}.json"
        data = rule.to_dict()
        indent = 2 if config.output.pretty_json else None
        json_path.write_text(json.dumps(data, indent=indent, default=str), encoding="utf-8")
        written.append(str(json_path))

    return written


# ---------------------------------------------------------------------------
# validate command
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--input", "-i", "input_path", required=True, type=click.Path(exists=True),
    help="Path to existing SIGMA rule YAML file."
)
@click.pass_context
def validate(ctx: click.Context, input_path: str) -> None:
    """Validate an existing SIGMA rule YAML file.

    Checks structural validity against the SIGMA specification and prints
    a detailed report. Exits with code 1 if the rule is invalid.
    """
    validator = SigmaValidator()
    yaml_str = Path(input_path).read_text(encoding="utf-8")
    is_valid, errors = validator.validate_yaml(yaml_str)

    if is_valid:
        console.print(
            Panel(
                f"[green bold]✓ YAML structure is valid[/]\n[dim]{input_path}[/]",
                title="Validation Result",
                border_style="green",
            )
        )
    else:
        error_lines = "\n".join(f"  • {e}" for e in errors)
        console.print(
            Panel(
                f"[red bold]✗ Validation failed[/]\n[dim]{input_path}[/]\n\n{error_lines}",
                title="Validation Result",
                border_style="red",
            )
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# batch command
# ---------------------------------------------------------------------------


@cli.command()
@click.option(
    "--input-dir", "-i", "input_dir", required=True, type=click.Path(exists=True),
    help="Directory containing input files (.txt, .md)."
)
@click.option(
    "--output-dir", "-o", "output_dir", default="./output",
    help="Directory for generated rule files."
)
@click.option(
    "--format", "output_format", default="yaml",
    type=click.Choice(["yaml", "json", "both"]),
    help="Output format for rule files."
)
@click.pass_context
def batch(ctx: click.Context, input_dir: str, output_dir: str, output_format: str) -> None:
    """Process a directory of threat intelligence files and generate SIGMA rules.

    Processes all .txt and .md files in the input directory. Shows a progress
    bar and writes all generated rules to the output directory.
    """
    config: AppConfig = ctx.obj["config"]
    config.output.output_dir = output_dir
    config.output.formats = [output_format] if output_format != "both" else ["yaml", "json"]

    in_path = Path(input_dir)
    input_files = sorted(list(in_path.glob("*.txt")) + list(in_path.glob("*.md")))

    if not input_files:
        console.print(f"[yellow]No .txt or .md files found in {input_dir}[/]")
        return

    gen = SigmaGenerator(config)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    total_rules = 0
    failed_files: list[str] = []

    import asyncio

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[status]}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Generating rules…",
            total=len(input_files),
            status="",
        )

        for file_path in input_files:
            progress.update(task, description=f"Processing {file_path.name}", status="…")

            result: GenerationResult = asyncio.run(
                gen.generate_from_file(file_path, author=config.generator.default_author)
            )

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

            if result.success and result.rules:
                for rule in result.rules:
                    _write_rule_output(rule, out_dir, timestamp, output_format, config)
                total_rules += len(result.rules)
                status_msg = f"[green]{len(result.rules)} rule(s)[/]"
            else:
                failed_files.append(file_path.name)
                status_msg = f"[red]failed[/]"

            progress.update(task, advance=1, status=status_msg)

    console.print(f"\n[bold]Batch complete[/]: {total_rules} rules generated from {len(input_files)} files")
    if failed_files:
        console.print(f"[yellow]Failed:[/] {', '.join(failed_files)}")
    console.print(f"[dim]Output:[/] {output_dir}")


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------


@cli.command()
def version() -> None:
    """Print the sigma-generator version."""
    console.print(f"sigma-generator {__version__}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Package entry point — invoked by the sigma-generator console script."""
    cli(obj={})


if __name__ == "__main__":
    main()
