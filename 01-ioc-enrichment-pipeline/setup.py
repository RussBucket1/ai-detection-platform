"""Package setup for the IOC enrichment pipeline."""
from __future__ import annotations

from pathlib import Path

from setuptools import find_packages, setup

_HERE = Path(__file__).parent
_REQUIREMENTS = (_HERE / "requirements.txt").read_text().splitlines()

install_requires = [
    line.strip()
    for line in _REQUIREMENTS
    if line.strip() and not line.startswith("#") and not line.startswith("pytest")
]

setup(
    name="ioc-enricher",
    version="1.0.0",
    description="Async IOC enrichment pipeline for Detection Engineering",
    author="Detection Engineering",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests*"]),
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "ioc-enricher=ioc_enricher.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
