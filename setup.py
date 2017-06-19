"""Setuptools package definition"""

from setuptools import setup
from setuptools import find_packages
from setuptools.command.install import install
import codecs
import os
import sys

__version__  = None
version_file = "pyark/version.py"
with codecs.open(version_file, encoding="UTF-8") as f:
    code = compile(f.read(), version_file, 'exec')
    exec(code)

with codecs.open('README.rst', 'r', encoding="UTF-8") as f:
    README_TEXT = f.read()

setup(
    name = "pyark",
    version = __version__,
    packages = find_packages(),
    entry_points = {
        'console_scripts': [
            "pyark = pyark:main",
        ]
    },
    install_requires = [
        "requests",
    ],
    author = "Adfinis SyGroup AG",
    author_email = "info@adfinis-sygroup.ch",
    description = ("Pyark is a small python-based CLI tool, which allows you to "
                  "interact with the CyberArk Enterprise Password Vault API."),
    long_description = README_TEXT,
    keywords = "CyberArk, Password Vault, API, CLI",
    url = "https://github.com/adfinis-sygroup/pyark",
    classifiers = [
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.5",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ]
)
