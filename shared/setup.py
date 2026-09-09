from setuptools import setup, find_packages

setup(
    name="asm-shared",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["sqlalchemy[asyncio]==2.0.35"],
)
