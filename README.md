# File Integrity Monitor

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](https://github.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Created By](https://img.shields.io/badge/Created%20By-0xtor.exe-red.svg)](#credits)

<p align="center">
  <img src="assets/logo/logo.png" alt="File Integrity Monitor Logo" width="200"/>
</p>

<p align="center">
  <b>A powerful file integrity monitoring tool using SHA-256 cryptographic hashing to detect unauthorized modifications, additions, and deletions.</b>
</p>

<p align="center">
  <b>Created by: 0xtor.exe</b>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [GUI Application](#gui-application)
- [CLI Usage](#cli-usage)
- [How It Works](#how-it-works)
- [Configuration](#configuration)
- [Testing](#testing)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

---

## Overview

File Integrity Monitor (FIM) is a security tool that helps you detect unauthorized changes to files by maintaining cryptographic hashes of your monitored files. Using the SHA-256 algorithm, it creates a baseline of file states and can identify when files are modified, added, or deleted.

This tool is perfect for:
- Monitoring critical system configuration files
- Detecting unauthorized changes to source code
- Verifying backup integrity
- Learning cybersecurity and digital forensics concepts
- Host-based intrusion detection

---

## Features

### Core Features
- **SHA-256 Hashing** - Cryptographically secure file hashing for reliable change detection
- **Baseline Management** - Create and store trusted snapshots of file states
- **Change Detection** - Identify modified, added, and deleted files
- **Recursive Scanning** - Monitor entire directory trees
- **JSON Reports** - Machine-readable output for automation and SIEM integration

### GUI Features (Native Desktop App)
- **Modern GTK4 Interface** - Clean, intuitive libadwaita-based interface
- **Visual Reports** - Color-coded changes with detailed hash comparisons
- **File Browser** - Built-in directory picker
- **History Tracking** - Keep track of recent scans
- **Real-time Status** - Live baseline and scan status indicators

### CLI Features
- **Lightweight & Fast** - No dependencies, pure Python standard library
- **Automation Ready** - Exit codes for scripting and cron jobs
- **Flexible Options** - Custom baselines, exclude patterns, and more
- **Cross-Platform** - Works on Linux, Windows, and macOS

---

## Project Structure

```
file_integrity_monitor/
│
├── assets/                      # Application assets
│   ├── icons/                   # Application icons (multiple sizes)
│   └── logo/                    # Logo files
│       ├── logo.png            # Original logo
│       └── fim-logo.png        # Application logo
│
├── docs/                        # Documentation
├── file_integrity/              # Core application package
│   ├── __init__.py             # Package initialization (0xtor.exe)
│   ├── baseline.py             # Baseline management module
│   ├── checker.py              # Integrity checking logic
│   ├── cli.py                  # Command-line interface
│   ├── errors.py               # Custom exceptions
│   ├── gui.py                  # Native GTK4 GUI application
│   ├── hasher.py               # SHA-256 hashing engine
│   ├── report.py               # Report generation
│   ├── scanner.py              # Directory scanning module
│   ├── service.py              # Shared business logic
│
├── scripts/                     # Additional launchers
│   ├── FileIntegrityMonitor    # Desktop launcher
│   ├── fim-gui.py             # GUI launcher script
│   ├── file_integrity_monitor.py
│   └── run_fim_gui.py
│
├── tests/                       # Test suite
│   ├── test_fim.py             # CLI and core tests
│
├── FileIntegrityMonitor        # Main GUI executable
├── fim.py                      # CLI entry point
├── fim-gui.py                  # GUI launcher (root)
├── README.md                   # This file
├── run_fim_gui.py             # GUI launcher (root)
└── synopsis.md                # Project synopsis
```

---

## Prerequisites

### For CLI Usage
- **Python 3.8 or higher** - [Download Python](https://www.python.org/downloads/)
- **No external dependencies required** - Uses only Python standard library

### For GUI Usage (Native Desktop)
- **Linux with GTK4 and libadwaita** (recommended)
- **Python 3.8+** with PyGObject
- **Display server**: X11 or Wayland

Check if you have the required packages:

```bash
# On Debian/Ubuntu/Kali
dpkg -l | grep -E 'gir1.2-gtk-4.0|gir1.2-adw-1'

# On Fedora
rpm -qa | grep -E 'gtk4|libadwaita'
```

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/file-integrity-monitor.git
cd file-integrity-monitor
```

### Step 2: Make Launchers Executable (Linux/macOS)

```bash
chmod +x FileIntegrityMonitor fim.py fim-gui.py run_fim_gui.py
```

### Step 3: (Optional) Install System-Wide

```bash
# Create a symlink to /usr/local/bin
sudo ln -s $(pwd)/fim.py /usr/local/bin/fim
sudo ln -s $(pwd)/FileIntegrityMonitor /usr/local/bin/file-integrity-monitor
```

---

## Usage

### GUI Application (Recommended)

Launch the native desktop application:

```bash
# Method 1: Direct executable
./FileIntegrityMonitor

# Method 2: Python module
python3 -m file_integrity.gui

# Method 3: Using launcher scripts
python3 fim-gui.py
python3 run_fim_gui.py
```

**GUI Workflow:**
1. **Select Directory** - Browse or enter the path to monitor
2. **Create Baseline** - Click "Create Baseline" to record current state
3. **Run Check** - Click "Run Check" to detect any changes
4. **View Results** - See color-coded modified/added/deleted files with hash details

---

### CLI Usage

#### Create a Baseline

Record the trusted state of a directory:

```bash
python3 fim.py baseline /path/to/directory
```

**Example:**
```bash
mkdir -p ~/test-monitor
echo "important config" > ~/test-monitor/config.txt
python3 fim.py baseline ~/test-monitor
```

**Output:**
```
Baseline created
  File:      /home/user/test-monitor/.fim_baseline.json
  Root:      /home/user/test-monitor
  Files:     1
  Algorithm: SHA-256
```

#### Check for Changes

Compare current state against the baseline:

```bash
python3 fim.py check /path/to/directory
```

**Example with changes:**
```bash
echo "modified config" > ~/test-monitor/config.txt
echo "new file" > ~/test-monitor/new.txt
python3 fim.py check ~/test-monitor
```

**Output:**
```
File Integrity Monitor
Root:      /home/user/test-monitor
Baseline:  /home/user/test-monitor/.fim_baseline.json
Created:   2026-10-24 01:30:00 IST
Algorithm: SHA-256

  ~ MODIFIED  config.txt
              sha256 abc123... -> def456...
              size   16 B -> 17 B
  + ADDED     new.txt
              sha256 ghi789...
              size   9 B

Scanned 2 files: 1 modified, 1 added, 0 deleted, 0 unchanged
Result: CHANGES DETECTED
```

#### Advanced CLI Options

```bash
# Use custom baseline location
python3 fim.py baseline /path/to/dir --baseline /path/to/custom-baseline.json

# Exclude files/directories
python3 fim.py baseline /path/to/dir --exclude "*.log" --exclude "cache/*" --exclude "__pycache__/*"

# Force overwrite existing baseline
python3 fim.py baseline /path/to/dir --force

# JSON output for automation
python3 fim.py check /path/to/dir --json

# Disable colored output
python3 fim.py check /path/to/dir --no-color

# Show help
python3 fim.py --help
python3 fim.py baseline --help
python3 fim.py check --help
```

#### Run as Module

```bash
python3 -m file_integrity baseline /path/to/dir
python3 -m file_integrity check /path/to/dir
```

---

## How It Works

The File Integrity Monitor follows a systematic 5-module approach:

| Module | Purpose | Implementation |
| --- | --- | --- |
| **1. Directory Scanner** | Discovers files to monitor | Recursively walks directory tree, skips symlinks and special files |
| **2. Hash Generator** | Computes cryptographic hashes | Streams files in 1MB chunks through `hashlib.sha256()` |
| **3. Baseline Manager** | Stores trusted state | Saves file paths and hashes to JSON with atomic writes and 0600 permissions |
| **4. Integrity Checker** | Compares states | Identifies files present in both (modified if hash differs), only in baseline (deleted), or only currently (added) |
| **5. Alert & Report** | Presents results | Generates human-readable or JSON reports with change details |

### Baseline File Format

```json
{
  "version": 1,
  "algorithm": "sha256",
  "created": "2026-10-24T01:30:00+00:00",
  "root": "/path/to/monitored/directory",
  "file_count": 2,
  "files": {
    "config.txt": {
      "sha256": "abc123...",
      "size": 16,
      "mtime": 1729722600.0
    }
  }
}
```

---

## Configuration

### Exclude Patterns

Use glob patterns to skip certain files or directories:

```bash
python3 fim.py baseline ./project --exclude "*.log" --exclude "*.tmp" --exclude "node_modules/*"
```

**Important:** Use the same exclude patterns for both `baseline` and `check` commands.

### Custom Baseline Location

Store baselines outside the monitored directory for added security:

```bash
python3 fim.py baseline ./sensitive-data --baseline ~/.secure/sensitive-data.baseline.json
```

---

## Testing

Run the complete test suite:

```bash
# Run all tests
python3 -m unittest discover -v

# Run specific test modules
python3 -m unittest tests.test_fim -v
```

**Test Coverage:**
- ✅ SHA-256 hashing (known values, empty files, large files)
- ✅ Directory scanning and exclusions
- ✅ Baseline creation, loading, and validation
- ✅ Change detection (modified, added, deleted)
- ✅ CLI commands and exit codes
- ✅ JSON output format
- ✅ Error handling

All 43 tests pass successfully.

---

## Security Considerations

### Best Practices
- **Protect your baseline** - Store baselines in secure locations with restricted permissions
- **Use read-only baselines** - Consider storing baselines on read-only media for critical systems
- **Run as appropriate user** - Only scan directories you have permission to access
- **Regular checks** - Schedule periodic integrity checks using cron/Task Scheduler
- **Secure storage** - If an attacker can modify both files and baseline, changes won't be detected

### Limitations
- **No real-time monitoring** - Scans are manual/on-demand
- **Content-only comparison** - Doesn't track permissions, ownership, or ACLs
- **Baseline vulnerability** - Baseline itself must be protected
- **Symlinks ignored** - Symlinks are not followed for security reasons
- **No automatic remediation** - Only detects changes, doesn't prevent them

---

## Troubleshooting

### Common Issues

**Issue: "baseline not found"**
```bash
# Solution: Create a baseline first
python3 fim.py baseline /path/to/directory
```

**Issue: "Permission denied" errors**
```bash
# Solution: Run with appropriate permissions or exclude unreadable files
# The tool will warn about unreadable files instead of failing
```

**Issue: GUI doesn't launch on Linux**
```bash
# Install GTK4 and PyGObject
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1
```

**Issue: Module not found errors**
```bash
# Ensure you're in the project directory
cd /path/to/file_integrity_monitor
python3 fim.py --version
```

---

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## Credits

**Created and Developed by: 0xtor.exe**

- **Author:** 0xtor.exe
- **Project Type:** Cybersecurity / File Integrity Monitoring
- **Language:** Python 3
- **GUI Framework:** GTK4 + Libadwaita
- **Hashing Algorithm:** SHA-256

Special thanks to the cybersecurity community for inspiration and best practices.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Made with ❤️ by 0xtor.exe</b>
</p>

<p align="center">
  <i>Stay secure. Monitor your files.</i>
</p>
