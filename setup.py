from setuptools import setup, find_packages

setup(
    name="audit-securite",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "typer[all]"
    ],
    entry_points={
        "console_scripts": [
            "audit-securite=audit_securite.main:main"
        ]
    },
)