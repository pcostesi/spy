#!/usr/bin/env python
from setuptools import Command, setup

setup(
    name='spy',
    version='0.3.6',
    url='http://github.com/pcostesi/spy/',
    license='BSD',
    author='Pablo Alejandro Costesich',
    author_email='pcostesi@alu.itba.edu.ar',
    description='A compiler suite for a research language',
#    long_description=__doc__,
    packages=['spy'],
    zip_safe=True,
    platforms='any',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
