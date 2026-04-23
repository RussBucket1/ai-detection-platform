"""Package setup for sigma-generator."""
from __future__ import annotations

from setuptools import find_packages, setup

setup(
    name="sigma-generator",
    version="1.0.0",
    description="AI-powered SIGMA detection rule generator using Claude",
    author="AI Detection Platform",
    python_requires=">=3.11",
    packages=find_packages(exclude=["tests*"]),
    install_requires=[
        "anthropic>=0.25.0,<1.0.0",
        "pydantic>=2.5.0,<3.0.0",
        "pydantic-settings>=2.1.0,<3.0.0",
        "click>=8.1.7,<9.0.0",
        "rich>=13.7.0,<14.0.0",
        "pyyaml>=6.0.1,<7.0.0",
        "python-dotenv>=1.0.0,<2.0.0",
        "ruamel.yaml>=0.18.0,<1.0.0",
        "jinja2>=3.1.3,<4.0.0",
        "orjson>=3.9.10,<4.0.0",
        "structlog>=24.1.0,<25.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.4,<8.0.0",
            "pytest-asyncio>=0.23.3,<1.0.0",
            "pytest-mock>=3.12.0,<4.0.0",
            "pytest-cov>=4.1.0,<5.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "sigma-generator=sigma_generator.__main__:main",
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
