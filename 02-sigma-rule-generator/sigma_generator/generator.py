"""Core orchestration engine — SigmaGenerator drives the full generation pipeline."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import anthropic

from sigma_generator.models.sigma import GenerationResult, SigmaRule, ValidationResult
from sigma_generator.parser import RuleParser
from sigma_generator.prompts.system import SIGMA_SYSTEM_PROMPT
from sigma_generator.prompts.templates import PromptBuilder
from sigma_generator.utils.config import AppConfig
from sigma_generator.utils.logger import get_logger
from sigma_generator.validator import SigmaValidator

logger = get_logger(__name__)


class SigmaGenerator:
    """Orchestrates the full SIGMA rule generation pipeline.

    Drives PromptBuilder → Anthropic LLM → RuleParser → SigmaValidator
    and returns a GenerationResult regardless of success or failure.
    """

    def __init__(self, config: AppConfig) -> None:
        """Initialise the generator with application configuration.

        Args:
            config: Application configuration containing LLM credentials,
                output settings, and generator behaviour flags.
        """
        self._config = config
        self._model = config.llm.model
        self._max_tokens = config.llm.max_tokens
        self._temperature = config.llm.temperature

        api_key = config.llm.api_key or None
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

        self._prompt_builder = PromptBuilder()
        self._parser = RuleParser()
        self._validator = SigmaValidator()

        logger.info(
            "SigmaGenerator initialised",
            model=self._model,
            validate=config.generator.validate_output,
            min_confidence=config.generator.min_confidence_threshold,
        )

    async def generate(
        self,
        content: str,
        input_type: str | None = None,
        author: str | None = None,
    ) -> GenerationResult:
        """Run the full generation pipeline for a single piece of threat intelligence.

        Steps:
          1. Build a type-appropriate prompt via PromptBuilder
          2. Call the Anthropic Messages API
          3. Parse the LLM response into SigmaRule objects
          4. Validate each rule
          5. Apply confidence threshold and author override

        All exceptions are caught and returned in GenerationResult.error so
        callers never need to handle exceptions from this method.

        Args:
            content: Raw threat intelligence text.
            input_type: Force a specific input type; auto-detected if None.
            author: Override the author field on generated rules.

        Returns:
            GenerationResult describing success/failure and all generated rules.
        """
        start_ms = time.monotonic() * 1000

        try:
            prompt, detected_type = self._prompt_builder.build_prompt(content, input_type)
            logger.info("Prompt built", detected_type=detected_type, prompt_chars=len(prompt))

            response_text = await self._call_llm(prompt)

            rules, analysis_summary = self._parser.parse_response(response_text)
            logger.info("Parsed rules from LLM", count=len(rules))

            effective_author = author or self._config.generator.default_author
            filtered: list[SigmaRule] = []

            for rule in rules:
                rule.author = effective_author

                if self._config.generator.validate_output:
                    result: ValidationResult = self._validator.validate_rule(rule)
                    if not result.valid:
                        logger.warning(
                            "Rule failed validation — excluded from output",
                            title=rule.title,
                            errors=result.errors,
                        )
                        continue
                    if result.warnings:
                        logger.info(
                            "Rule has validation warnings",
                            title=rule.title,
                            warnings=result.warnings,
                        )

                min_conf = self._config.generator.min_confidence_threshold
                if rule.confidence_score < min_conf:
                    logger.info(
                        "Rule below confidence threshold — excluded",
                        title=rule.title,
                        score=rule.confidence_score,
                        threshold=min_conf,
                    )
                    continue

                filtered.append(rule)

            elapsed = time.monotonic() * 1000 - start_ms

            logger.info(
                "Generation complete",
                total_parsed=len(rules),
                total_kept=len(filtered),
                elapsed_ms=round(elapsed, 1),
            )

            return GenerationResult(
                success=True,
                rules=filtered,
                source_type=detected_type,
                source_summary=analysis_summary,
                total_generated=len(filtered),
                generation_time_ms=round(elapsed, 1),
                model_used=self._model,
            )

        except anthropic.AuthenticationError as exc:
            elapsed = time.monotonic() * 1000 - start_ms
            msg = (
                "Anthropic API authentication failed. "
                "Verify your ANTHROPIC_API_KEY is correct and not expired."
            )
            logger.error("Authentication error", error=str(exc), hint=msg)
            return GenerationResult(
                success=False,
                model_used=self._model,
                generation_time_ms=round(elapsed, 1),
                error=f"Authentication error: {exc}",
            )

        except anthropic.RateLimitError as exc:
            elapsed = time.monotonic() * 1000 - start_ms
            msg = (
                "Anthropic API rate limit reached. "
                "Wait a moment before retrying, or check your usage tier."
            )
            logger.error("Rate limit error", error=str(exc), hint=msg)
            return GenerationResult(
                success=False,
                model_used=self._model,
                generation_time_ms=round(elapsed, 1),
                error=f"Rate limit error: {exc}",
            )

        except anthropic.APIError as exc:
            elapsed = time.monotonic() * 1000 - start_ms
            logger.error("Anthropic API error", error=str(exc), error_type=type(exc).__name__)
            return GenerationResult(
                success=False,
                model_used=self._model,
                generation_time_ms=round(elapsed, 1),
                error=f"API error ({type(exc).__name__}): {exc}",
            )

        except Exception as exc:
            elapsed = time.monotonic() * 1000 - start_ms
            logger.error(
                "Unexpected error during generation",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return GenerationResult(
                success=False,
                model_used=self._model,
                generation_time_ms=round(elapsed, 1),
                error=f"Unexpected error ({type(exc).__name__}): {exc}",
            )

    async def _call_llm(self, prompt: str) -> str:
        """Send the user prompt to the Anthropic Messages API and return the text.

        Args:
            prompt: Rendered user prompt to send.

        Returns:
            Raw response text from the model.

        Raises:
            anthropic.AuthenticationError: On bad API key.
            anthropic.RateLimitError: On rate limit exceeded.
            anthropic.APIError: On any other Anthropic API error.
        """
        logger.debug(
            "Calling Anthropic API",
            model=self._model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
        )
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
            system=SIGMA_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text
        logger.debug("LLM response received", chars=len(text))
        return text

    async def generate_from_file(
        self,
        path: str | Path,
        input_type: str | None = None,
        author: str | None = None,
    ) -> GenerationResult:
        """Read a file and run the generation pipeline on its content.

        Supports .txt, .md, .json, .yaml/.yml files. For JSON/YAML files the
        content is serialised back to a string for the prompt context.

        Args:
            path: Path to the input file.
            input_type: Force input type (skips auto-detection).
            author: Override author field on generated rules.

        Returns:
            GenerationResult (error set if file cannot be read).
        """
        file_path = Path(path)

        if not file_path.exists():
            logger.error("Input file not found", path=str(file_path))
            return GenerationResult(
                success=False,
                model_used=self._model,
                error=f"File not found: {file_path}",
            )

        try:
            suffix = file_path.suffix.lower()
            if suffix in {".json"}:
                import json

                raw = json.loads(file_path.read_text(encoding="utf-8"))
                content = json.dumps(raw, indent=2)
            elif suffix in {".yaml", ".yml"}:
                content = file_path.read_text(encoding="utf-8")
            else:
                content = file_path.read_text(encoding="utf-8")

            logger.info("File read", path=str(file_path), chars=len(content))
        except Exception as exc:
            logger.error("Failed to read input file", path=str(file_path), error=str(exc))
            return GenerationResult(
                success=False,
                model_used=self._model,
                error=f"Failed to read {file_path}: {exc}",
            )

        return await self.generate(content, input_type=input_type, author=author)

    def generate_sync(self, content: str, **kwargs: Any) -> GenerationResult:
        """Synchronous wrapper around generate() for CLI and scripting use.

        Args:
            content: Raw threat intelligence text.
            **kwargs: Forwarded to generate() (input_type, author).

        Returns:
            GenerationResult.
        """
        return asyncio.run(self.generate(content, **kwargs))
