"""
Setup script for Jarvis - Terminal-based peer-to-peer encrypted messenger.

Created by orpheus497

This messenger provides:
- Peer-to-peer direct connections (no servers)
- Five-layer encryption (AES-256-GCM + ChaCha20-Poly1305)
- Group chat functionality
- Cross-platform terminal UI (Linux, Windows, macOS, Termux)
- Background operation with notifications
- Complete offline capability
"""

from setuptools import setup, find_packages
import os

this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='jarvis-messenger',
    version='1.2.0',
    author='orpheus497',
    description='A terminal-based peer-to-peer end-to-end encrypted messenger with multi-layer encryption and group chat',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/orpheus497/jarvis',
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: End Users/Desktop',
        'Topic :: Communications :: Chat',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: OS Independent',
        'Environment :: Console',
    ],
    python_requires='>=3.8',
    install_requires=[
        'textual>=0.47.0',
        'cryptography>=42.0.4',
        'argon2-cffi>=23.1.0',
        'rich>=13.7.0',
    ],
    entry_points={
        'console_scripts': [
            'jarvis=jarvis.__main__:main',
            'jarvis-server=jarvis.server:main',
        ],
    },
)
