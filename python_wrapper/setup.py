"""
Setup script for WAF + Reverse Proxy Python Wrapper
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8') if (this_directory / "README.md").exists() else ""

# Read requirements from requirements.txt
def parse_requirements(filename):
    """Parse requirements from requirements.txt file"""
    try:
        with open(filename, 'r') as f:
            requirements = []
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#'):
                    # Remove inline comments
                    if '#' in line:
                        line = line.split('#')[0].strip()
                    # Skip optional dependencies marked as such
                    if 'optional' not in line.lower():
                        requirements.append(line)
            return requirements
    except FileNotFoundError:
        return []

install_requires = parse_requirements('requirements.txt')

# Filter out development dependencies
dev_keywords = ['pytest', 'black', 'flake8', 'mypy', 'optional']
install_requires = [
    req for req in install_requires 
    if not any(keyword in req.lower() for keyword in dev_keywords)
]

setup(
    name="waf-proxy-wrapper",
    version="1.0.0",
    author="Deepskilling",
    author_email="support@deepskilling.com",
    description="Python wrapper for WAF + Reverse Proxy by Deepskilling",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/deepskilling/waf-reverse-proxy",
    project_urls={
        "Bug Tracker": "https://github.com/deepskilling/waf-reverse-proxy/issues",
        "Documentation": "https://github.com/deepskilling/waf-reverse-proxy/docs",
        "Source Code": "https://github.com/deepskilling/waf-reverse-proxy",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=install_requires,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.20.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
        ],
        "cli": [
            "rich>=12.0.0",
            "click>=8.0.0",
        ],
        "validation": [
            "pydantic>=1.10.0",
            "marshmallow>=3.19.0",
        ],
        "monitoring": [
            "structlog>=22.0.0",
            "prometheus-client>=0.15.0",
        ],
        "all": [
            "rich>=12.0.0",
            "click>=8.0.0",
            "pydantic>=1.10.0",
            "marshmallow>=3.19.0",
            "structlog>=22.0.0",
            "prometheus-client>=0.15.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "waf-proxy=waf_proxy.cli:main",
            "waf-proxy-cli=waf_proxy.cli:main",
            "waf-proxy-wrapper=waf_proxy.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "waf_proxy": [
            "templates/*.yaml",
            "templates/*.json",
            "examples/*.py",
        ],
    },
    zip_safe=False,
    keywords=[
        "waf",
        "web application firewall",
        "reverse proxy",
        "security",
        "ddos protection",
        "rate limiting",
        "load balancing",
        "ssl termination",
        "rust",
        "deepskilling",
    ],
)
