#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : setup.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

import setuptools

long_description = """
"""

with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [x.strip() for x in f.readlines()]

setuptools.setup(
    name="sharehound",
    version="1.0.2" ,
    description="A Python script to generate a bloodhound opengraph of the rights of shares on a remote Windows machine.",
    url="https://github.com/p0dalirius/ShareHound",
    author="Podalirius",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email="podalirius@protonmail.com",
    packages=["sharehound", "sharehound.core"],
    package_data={'sharehound': ['sharehound/collector/', 'sharehound/core/', 'sharehound/utils/']},
    include_package_data=True,
    license="GPL2",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.11',
    install_requires=requirements,
    entry_points={
        'console_scripts': ['sharehound=sharehound.__main__:main']
    }
)
