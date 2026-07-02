"""Package setup for triage-assistant."""
from __future__ import annotations

from setuptools import find_packages, setup

setup(
    name="triage-assistant",
    version="1.0.0",
    description="RAG-based SIEM alert triage assistant using IOC intelligence, SIGMA rules, and MITRE ATT&CK",
    python_requires=">=3.11",
    packages=find_packages(),
    install_requires=[
        "anthropic>=0.25.0,<1.0.0",
        "fastapi>=0.111.0,<1.0.0",
        "uvicorn[standard]>=0.29.0,<1.0.0",
        "chromadb>=0.5.0,<1.0.0",
        "sentence-transformers>=2.7.0,<3.0.0",
        "pydantic>=2.5.0,<3.0.0",
        "pydantic-settings>=2.1.0,<3.0.0",
        "click>=8.1.7,<9.0.0",
        "rich>=13.7.0,<14.0.0",
        "pyyaml>=6.0.1,<7.0.0",
        "ruamel.yaml>=0.18.0,<1.0.0",
        "python-dotenv>=1.0.0,<2.0.0",
        "orjson>=3.9.10,<4.0.0",
        "structlog>=24.1.0,<25.0.0",
        "httpx>=0.27.0,<1.0.0",
        "requests>=2.31.0,<3.0.0",
        "jinja2>=3.1.3,<4.0.0",
    ],
    entry_points={
        "console_scripts": [
            "triage-assistant=triage_assistant.__main__:main",
        ],
    },
)
