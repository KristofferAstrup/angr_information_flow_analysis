from setuptools import find_packages, setup
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='information_flow_analysis',
    packages=find_packages(include=['information_flow_analysis']),
    version='0.1.4',
    description='Information Flow Control library for binaries using angr',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Kristoffer Astrup and Sebastian Olsen',
    license='MIT',
    install_requires=['angr','angr-utils','pydot','bingraphvis','networkx','matplotlib'],
    setup_requires=['angr','angr-utils','pydot','bingraphvis','networkx','matplotlib'],
)