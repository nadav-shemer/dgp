# -*- coding: utf-8 -*-
"""
    Dgp Tests
    ~~~~~~~~~~~~

    Tests the Dgp application.

    :copyright: (c) 2015 by dgp author.
    :license: BSD, see LICENSE for more details.
"""

from setuptools import setup, find_packages

setup(
    name='dgp',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'flask',
    ],
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=[
        'pytest',
    ],
)
