#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from setuptools import setup

version = re.search(r'__version__\s*=\s*"(.+)"', open('getsploit/getsploit.py', 'rt').read()).group(1)


long_description = '''
getsploit
=========

Command line search and download tool for Vulners Database inspired by
searchsploit. It allows you to search online for the exploits across all the
most popular collections: Exploit-DB, Metasploit, Packetstorm and others. The
most powerful feature is immediate exploit source download right in your
working path.
'''

setup(
    name='getsploit',
    packages=['getsploit'],
    version=version,
    description='Command line search and download tool for Vulners Database \
inspired by searchsploit.',
    long_description=long_description,
    license='LGPLv3',
    url='https://github.com/vulnersCom/getsploit',
    author='Kirill Ermakov',
    author_email='isox@vulners.com',
    maintainer="Kir Ermakov",
    entry_points={
        'console_scripts': [
            'getsploit = getsploit.getsploit:main',
        ]
    },
    install_requires = [
            'vulners',
            'six',
            'texttable',
            'clint',
        ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Topic :: Security",
    ]
)
