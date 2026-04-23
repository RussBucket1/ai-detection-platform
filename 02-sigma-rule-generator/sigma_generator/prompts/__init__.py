"""Prompt system for SIGMA rule generation."""
from __future__ import annotations

from sigma_generator.prompts.system import SIGMA_SYSTEM_PROMPT
from sigma_generator.prompts.templates import PromptBuilder, PromptTemplate

__all__ = ["SIGMA_SYSTEM_PROMPT", "PromptBuilder", "PromptTemplate"]
