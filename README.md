# FortiAnalyzer – Fortigate Traffic Log Analyzer

A Python automation tool that parses Fortigate application-control logs
and generates a formatted Excel dashboard with charts and weekly comparisons.

## Features
- Parses Fortigate `.log` files (key=value format)
- Aggregates traffic by device, application, domain and hour
- Classifies traffic into categories (Streaming, Business, Infra, Risk…)
- Detects Shadow IT (unapproved applications)
- Compares current week vs previous week
- Exports a multi-sheet `.xlsx` dashboard with embedded charts

## Project Structure
```
project/
├── input/              # Place .log files here
│   └── archive/        # Processed files are moved here automatically
├── output/             # Generated JSON summaries, reports and dashboard
└── scripts/
    ├── fortianalyzer.py      # Log parser and metrics engine
    ├── generate_dashboard.py # Excel dashboard generator
    ├── menu.py               # Interactive CLI launcher
    └── categories.json       # Category mapping config
```

## Requirements
```
pip install openpyxl
```

## Usage
```
python scripts/menu.py
```

## Tech Stack
Python 3.11+ · openpyxl · Standard Library (json, pathlib, collections, ipaddress)
