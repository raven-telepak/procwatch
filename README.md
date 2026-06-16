# ProcWatch

A lightweight process triage tool for macOS (Windows and Linux support potentially on the way). Designed to bridge the gap between technical and non-technical users who want to understand what's running on their machine and safely free up resources.

Primarily made to free up resources on older machines, is slowly spiraling into something more.

## Features
- [x] Enumerate all running processes with CPU and memory usage
- [x] Detect ghost processes (executable no longer exists on disk)
- [x] Flag suspicious processes running from unusual directories
- [x] Flag processes with active outbound network connections
- [x] SHA-256 hashing for unknown processes
- [x] Risk classification (Safe / Unknown / Suspicious)
- [x] Plain English explanations for non-technical users
- [ ] Safe process termination with verified kill list
- [ ] Autokill persistence per process
- [ ] Config mode
- [ ] Cross-platform support? (Windows, Linux)

## Usage
In progress!

## Disclaimer
This tool only operates in user space and will never attempt to terminate system-critical processes.
