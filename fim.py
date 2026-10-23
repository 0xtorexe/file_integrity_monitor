#!/usr/bin/env python3
"""Command-line entry point for the File Integrity Monitor.

Usage:
    python fim.py baseline <directory>
    python fim.py check <directory>
"""

from file_integrity.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
