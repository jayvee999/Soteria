from setuptools import setup, find_packages

setup(
    name="soteria",
    version="1.0.0",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0",
        "pyyaml>=6.0",
        "requests>=2.28",
        "bcrypt>=4.0",
        "httpx>=0.24",
        
    ],
    entry_points={
        "console_scripts": [
            "soteria=soteria.cli:main",
        ],
    },
)
