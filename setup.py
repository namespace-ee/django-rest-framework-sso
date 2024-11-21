# coding: utf-8
import os
from setuptools import find_packages, setup


INSTALL_REQUIRES = ["djangorestframework", "cryptography", "pem", "PyJWT"]


with open(os.path.join(os.path.dirname(__file__), "README.rst")) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))


setup(
    name="djangorestframework-sso",
    version="0.5.0",
    packages=find_packages(exclude=["tests"]),
    include_package_data=True,
    license="MIT License",
    description="Single sign-on extension to the Django REST Framework.",
    long_description=README,
    url="https://github.com/namespace-ee/django-rest-framework-sso",
    author="Lenno Nagel",
    author_email="lenno@namespace.ee",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    install_requires=INSTALL_REQUIRES,
)
